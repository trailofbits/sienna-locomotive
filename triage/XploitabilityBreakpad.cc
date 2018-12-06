// Modified exploitability_win.cc for SL2


// Copyright (c) 2010 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// exploitability_sl2.cc: Windows specific exploitability engine.
//
// Provides a guess at the exploitability of the crash for the Windows
// platform given a minidump and process_state.
//
// Author: Cris Neckar

#include <vector>

#include "XploitabilityBreakpad.h"
#include <iostream>

#include "common/scoped_ptr.h"
#include "google_breakpad/common/minidump_exception_win32.h"
#include "google_breakpad/processor/minidump.h"
#include "processor/disassembler_x86.h"
#include "processor/logging.h"

#include "third_party/libdisasm/libdis.h"

namespace sl2 {

// The cutoff that we use to judge if and address is likely an offset
// from various interesting addresses.
static const uint64_t kProbableNullOffset = 4096;
static const uint64_t kProbableStackOffset = 8192;

// The various cutoffs for the different ratings.
static const size_t kHighCutoff        = 100;
static const size_t kMediumCutoff      = 80;
static const size_t kLowCutoff         = 50;
static const size_t kInterestingCutoff = 25;

// Predefined incremental values for conditional weighting.
static const size_t kTinyBump          = 5;
static const size_t kSmallBump         = 20;
static const size_t kMediumBump        = 50;
static const size_t kLargeBump         = 70;
static const size_t kHugeBump          = 90;

// The maximum number of bytes to disassemble past the program counter.
static const size_t kDisassembleBytesBeyondPC = 2048;

XploitabilityBreakpad::XploitabilityBreakpad(Minidump *dump,
                                     ProcessState *process_state)
    : Xploitability(dump, process_state, "breakzpad") {       
    }

/**
 * Starts off with a weight of zero. Checks for a number of "interesting" conditions and increments the weight by
 * an appropriate amount each time it finds one.
 * @return The exploitability score
 */
ExploitabilityRating XploitabilityBreakpad::processExploitabilityRating() {
    uint64_t exploitabilityWeight = 0;

  // Check if we are executing on the stack.
  if (instructionPtr_ <= (stackPtr_ + kProbableStackOffset) &&
      instructionPtr_ >= (stackPtr_ - kProbableStackOffset))
    exploitabilityWeight += kHugeBump;

  switch (exceptionCode_) {
    // This is almost certainly recursion.
    case MD_EXCEPTION_CODE_WIN_STACK_OVERFLOW:
      exploitabilityWeight += kTinyBump;
      break;

    // These exceptions tend to be benign and we can generally ignore them.
    case MD_EXCEPTION_CODE_WIN_INTEGER_DIVIDE_BY_ZERO:
    case MD_EXCEPTION_CODE_WIN_INTEGER_OVERFLOW:
    case MD_EXCEPTION_CODE_WIN_FLOAT_DIVIDE_BY_ZERO:
    case MD_EXCEPTION_CODE_WIN_FLOAT_INEXACT_RESULT:
    case MD_EXCEPTION_CODE_WIN_FLOAT_OVERFLOW:
    case MD_EXCEPTION_CODE_WIN_FLOAT_UNDERFLOW:
    case MD_EXCEPTION_CODE_WIN_IN_PAGE_ERROR:
      exploitabilityWeight += kTinyBump;
      break;

    // These exceptions will typically mean that we have jumped where we
    // shouldn't.
    case MD_EXCEPTION_CODE_WIN_ILLEGAL_INSTRUCTION:
    case MD_EXCEPTION_CODE_WIN_FLOAT_INVALID_OPERATION:
    case MD_EXCEPTION_CODE_WIN_PRIVILEGED_INSTRUCTION:
      exploitabilityWeight += kLargeBump;
      break;

    // These represent bugs in exception handlers.
    case MD_EXCEPTION_CODE_WIN_INVALID_DISPOSITION:
    case MD_EXCEPTION_CODE_WIN_NONCONTINUABLE_EXCEPTION:
      exploitabilityWeight += kSmallBump;
      break;

    case MD_EXCEPTION_CODE_WIN_HEAP_CORRUPTION:
    case MD_EXCEPTION_CODE_WIN_STACK_BUFFER_OVERRUN:
      exploitabilityWeight += kHugeBump;
      break;

    case MD_EXCEPTION_CODE_WIN_GUARD_PAGE_VIOLATION:
      exploitabilityWeight += kLargeBump;
      break;

    case MD_EXCEPTION_CODE_WIN_ACCESS_VIOLATION:
      bool near_null = (process_state_->crash_address() <= kProbableNullOffset);
      bool bad_read = false;
      bool bad_write = false;
      if (rawException_->exception_record.number_parameters >= 1) {
        MDAccessViolationTypeWin av_type =
            static_cast<MDAccessViolationTypeWin>
            (rawException_->exception_record.exception_information[0]);
        switch (av_type) {
          case MD_ACCESS_VIOLATION_WIN_READ:
            bad_read = true;
            if (near_null)
              exploitabilityWeight += kSmallBump;
            else
              exploitabilityWeight += kMediumBump;
            break;
          case MD_ACCESS_VIOLATION_WIN_WRITE:
            bad_write = true;
            if (near_null)
              exploitabilityWeight += kSmallBump;
            else
              exploitabilityWeight += kHugeBump;
            break;
          case MD_ACCESS_VIOLATION_WIN_EXEC:
            if (near_null)
              exploitabilityWeight += kSmallBump;
            else
              exploitabilityWeight += kHugeBump;
            break;
          default:
            BPLOG(INFO) << "Unrecognized access violation type.";
            return EXPLOITABILITY_ERR_PROCESSING;
            break;
        }
        MinidumpMemoryRegion *instruction_region = 0;
        if (memoryAvailable_) {
          instruction_region =
              memoryList_->GetMemoryRegionForAddress(instructionPtr_);
        }
        if (!near_null && instruction_region &&
            context_->GetContextCPU() == MD_CONTEXT_X86 &&
            (bad_read || bad_write)) {
          // Perform checks related to memory around instruction pointer.
          uint32_t memory_offset =
              instructionPtr_ - instruction_region->GetBase();
          uint32_t available_memory =
              instruction_region->GetSize() - memory_offset;
          available_memory = available_memory > kDisassembleBytesBeyondPC ?
              kDisassembleBytesBeyondPC : available_memory;
          if (available_memory) {
            const uint8_t *raw_memory =
                instruction_region->GetMemory() + memory_offset;
            DisassemblerX86 disassembler(raw_memory,
                                         available_memory,
                                         instructionPtr_);
            disassembler.NextInstruction();
            if (bad_read)
              disassembler.setBadRead();
            else
              disassembler.setBadWrite();
            if (disassembler.currentInstructionValid()) {
              // Check if the faulting instruction falls into one of
              // several interesting groups.
              switch (disassembler.currentInstructionGroup()) {
                case libdis::insn_controlflow:
                  exploitabilityWeight += kLargeBump;
                  break;
                case libdis::insn_string:
                  exploitabilityWeight += kHugeBump;
                  break;
                default:
                  break;
              }
              // Loop the disassembler through the code and check if it
              // IDed any interesting conditions in the near future.
              // Multiple flags may be set so treat each equally.
              while (disassembler.NextInstruction() &&
                     disassembler.currentInstructionValid() &&
                     !disassembler.endOfBlock())
                continue;
              if (disassembler.flags() & DISX86_BAD_BRANCH_TARGET)
                exploitabilityWeight += kLargeBump;
              if (disassembler.flags() & DISX86_BAD_ARGUMENT_PASSED)
                exploitabilityWeight += kTinyBump;
              if (disassembler.flags() & DISX86_BAD_WRITE)
                exploitabilityWeight += kMediumBump;
              if (disassembler.flags() & DISX86_BAD_BLOCK_WRITE)
                exploitabilityWeight += kMediumBump;
              if (disassembler.flags() & DISX86_BAD_READ)
                exploitabilityWeight += kTinyBump;
              if (disassembler.flags() & DISX86_BAD_BLOCK_READ)
                exploitabilityWeight += kTinyBump;
              if (disassembler.flags() & DISX86_BAD_COMPARISON)
                exploitabilityWeight += kTinyBump;
            }
          }
        }
        if (!near_null && AddressIsAscii(process_state_->crash_address()))
          exploitabilityWeight += kMediumBump;
      } else {
        BPLOG(INFO) << "Access violation type parameter missing.";
        return EXPLOITABILITY_ERR_PROCESSING;
      }
  }

  // Based on the calculated weight we return a simplified classification.
  //std::cout << "Calculated exploitability weight: " << exploitabilityWeight;
  if (exploitabilityWeight >= kHighCutoff)
    return EXPLOITABILITY_HIGH;
  if (exploitabilityWeight >= kMediumCutoff)
    return EXPLOITABLITY_MEDIUM;
  if (exploitabilityWeight >= kLowCutoff)
    return EXPLOITABILITY_LOW;
  if (exploitabilityWeight >= kInterestingCutoff)
    return EXPLOITABILITY_INTERESTING;

  return EXPLOITABILITY_NONE;
}


/**
 * Converts a google breakpad rating to an sl2 result with a ranking
 * @param result - SL2 result we modify
 * @param rating - exploitabilty from Breakpad
 * @return the results that was passed in
 */
XploitabilityResult& operator<<( XploitabilityResult& result, const ExploitabilityRating& rating ) {
    switch(rating) {
        case EXPLOITABILITY_HIGH:
            result.rank = XploitabilityRank::XPLOITABILITY_HIGH;
            break;
        case EXPLOITABILITY_MEDIUM:
            result.rank = XploitabilityRank::XPLOITABILITY_MEDIUM;
            break;
        case EXPLOITABILITY_LOW:
            result.rank = XploitabilityRank::XPLOITABILITY_LOW;
            break;
        case EXPLOITABILITY_INTERESTING:
            result.rank = XploitabilityRank::XPLOITABILITY_UNKNOWN;
            break;
        default:
            result.rank = XploitabilityRank::XPLOITABILITY_NONE;

    }
    return result;
}

/**
 * wrapper around processExploitabilityRating
 * @return SL2 ranking from breakpad
 */
XploitabilityResult XploitabilityBreakpad::process() {
    XploitabilityResult result(name());
    ExploitabilityRating rating = processExploitabilityRating();

    result << rating;



    return result;
}

}  // namespace google_breakpad
