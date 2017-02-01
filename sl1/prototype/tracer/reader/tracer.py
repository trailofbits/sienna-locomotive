#!/usr/bin/env python2

try:
  import distorm3
except ImportError:
  class distorm3(object):
    Decode64Bits=1
    @classmethod
    def Decode(*a): return [['','','']]
import Trace_pb2
import sys
import struct
import argparse

class EndOfTraceException(Exception):
    pass

def read_lv(st, width=8):
  '''
   Read a [length, value] from a stream, st.

   Typically used for reading protobuf structs.
  '''
  count_bytes = st.read(width)
  if len(count_bytes) < width:
      raise EndOfTraceException()

  fmt = '@'

  if width == 8:
    fmt += 'Q'
  elif width == 4:
    fmt += 'L'
  elif width == 2:
    fmt += 'H'
  elif width == 1:
    fmt += 'B'
  else:
    raise ValueError("Size must be either 8, 4, 2, or 1")

  count = struct.unpack(fmt, count_bytes)[0]
  return st.read(count)


class ProtobufBacked(object):
  '''
   Base class for protobuf message-backed structs. Includes the ability to read
   a structure from a stream.

   Set backing_class to the type of the backing protobuf message.
 '''
  backing_class = None

  @classmethod
  def from_stream(cls, s):
    assert cls.backing_class
    header_bytes = read_lv(s)
    pb_header = cls.backing_class()
    pb_header.ParseFromString(header_bytes)
    return cls(pb_header)

class TraceHeader(ProtobufBacked):
  backing_class = Trace_pb2.TraceHeader

  def __init__(self, pb_header):
    self._cmdline = pb_header.cmdline
    self._width = pb_header.machine_width
    self._path = pb_header.path

  def path(self):
    return self._cmdline[0]

class RegisterMap(ProtobufBacked):
  backing_class = Trace_pb2.RegisterMap

  def __init__(self, regmap):
    self._register_names = {}
    self._register_indexes = {}
    for u in regmap.register_map:
      self._register_names[u.register_name] = u.register_number
      self._register_indexes[u.register_number] = u.register_name

  def get_name(self, idx):
    return self._register_indexes[idx]

  def get_idx(self, name):
    return self._register_names[name]

  def __len__(self):
    return len(self._register_names)


class TraceEvent(ProtobufBacked):
  backing_class = Trace_pb2.TraceEvent

  def __init__(self, pb_event):
    self.n = pb_event.n
    self.instruction = pb_event.instruction
    self.updated_regs = []
    for r in pb_event.regs:
      self.updated_regs.append( (r.register_number, r.register_value) )


class ExecutionState(object):
  def __init__(self, regmap):
    self._register_map = regmap
    self._registers = [0] * len(regmap)
    self._last_instruction = bytes()
    self._pc_idx = regmap.get_idx('rip')

  def update(self, trace_event):
    assert self._register_map

    for idx, val in trace_event.updated_regs:
      assert idx < len(self._register_map)
      self._registers[idx] = val
  
    self._last_instruction = trace_event.instruction

    return len(trace_event.updated_regs)

  def pc(self):
    return self._registers[self._pc_idx]

  def dump(self, s = sys.stdout):
    s.write('Instruction: %s\n'%(self._disassembled(),))
    s.write('Registers: \n')
    for idx, value in enumerate(self._registers):
      s.write('  %s: 0x%x\n'%
          (self._register_map.get_name(idx), self._registers[idx]))
    s.write('\n')

  def _disassembled(self):
    return distorm3.Decode(0,self._last_instruction,distorm3.Decode64Bits)[0][2]

class ExecutionTrace(object):
  def __init__(self, s):
    self._header = TraceHeader.from_stream(s)
    self._s = s

    regmap = RegisterMap.from_stream(s)
    self._state = ExecutionState(regmap)
    self._last_event = TraceEvent.from_stream(s)
    self._state.update(self._last_event)

  def state(self):
    return self._state

  def __iter__(self):
    return self

  def next(self):
    try:
      self._last_event = TraceEvent.from_stream(self._s)
      self._state.update(self._last_event)
      return self._last_event
    except EndOfTraceException:
      raise StopIteration


def main():
  parser = argparse.ArgumentParser(description='Consume an execution trace')
  parser.add_argument('input', type=str, help='path to the recorded trace')
  args = parser.parse_args()

  s = open(args.input, 'r')
  i = 0

  tracer = ExecutionTrace(s)
  for event in tracer:
    tracer.state().dump()

  return 

if __name__ == '__main__':
  main()
