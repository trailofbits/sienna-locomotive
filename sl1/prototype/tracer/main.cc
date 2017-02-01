// tracer main

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <unistd.h>
#include <sstream>


#include <capstone/capstone.h>

#include "Trace.pb.h"
#include "tracer.h"
#include "recorder.h"
#include "registerfile.h"

#define RECORD_INSTRUCTION_BYTES 1


using std::vector;
using std::string;

int main(int argc, char *argv[]) {
  boost::program_options::variables_map                   vm;
  boost::program_options::positional_options_description  pd;
  boost::program_options::options_description desc("Options");

  csh handle;
  cs_insn *insn;

  desc.add_options()
    ("text,t", "Store instruction as disassembly, instead of in raw form")
    ("input,i",  boost::program_options::value<vector<string>>()->required(), "Target program and arguments")
    ("output,o", boost::program_options::value<string>()->required(), "Trace destination")
    ("help,h", "Help")
  ;

   pd.add("input", -1);

  try {
    boost::program_options::store(
      boost::program_options::command_line_parser(argc, argv)
         .options(desc)
         .positional(pd)
         .run(), 
      vm);
    boost::program_options::notify(vm);    
  } catch (std::exception& e) {
    std::cout << "ERROR\n" << e.what() << "\n" << desc << "\n";
    return 1;
  } 

  if (vm.count("help")) {
    std::cout << desc << "\n";
    return 1;
  }

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    return 1;
  }


  auto input_args = vm["input"].as<vector<string>>();
  auto output = vm["output"].as<string>();
  size_t count;

  if (!boost::filesystem::exists(input_args[0])) {
    std::cerr << "File not found: " << input_args[0] << "\n";
    return 1;
  }

  Tracer instructionTracer {input_args};
  Recorder stateRecorder {output, input_args};
  RegisterFile previous;

  instructionTracer.addListener([&](const struct user_regs_struct &regs) {

    std::stringstream ss;
    uint64_t rip = (uint64_t) regs.rip;

    if(!instructionTracer.addressWithinImage(rip)) {
      return;
    } 

    RegisterFile current {&regs};

    // XXX: Delta is not used yet
    auto delta = current.getDelta(previous);

    vector<uint8_t> instruction_bytes;
    instruction_bytes = instructionTracer.getClientMemory(rip, 16);
    count = cs_disasm(handle, &instruction_bytes[0], 16, regs.rip, 1, &insn);
    if (vm.count("text")) {
      ss << insn->mnemonic << " " << insn->op_str;

      string txt = ss.str();
      instruction_bytes = vector<uint8_t>(txt.begin(), txt.end());
    } else {
      if (count == 1) {
        instruction_bytes.resize(insn->size);
      }
    }
    stateRecorder.recordState(Recorder::State{regs, instruction_bytes});

    previous = current;
  });

  instructionTracer.onComplete([](Tracer::ExitStatus status) {
    std::cout << "Finished with status: " << status << "\n";
  });

  instructionTracer.start();
}
