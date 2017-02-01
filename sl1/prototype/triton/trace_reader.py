#!/usr/bin/env python

import os
import sys
import struct

sys.path.append(os.path.join(os.path.dirname(__file__), "tob_lib"))
sys.path.append(os.path.dirname(__file__))

import Trace_pb2
import proc

class TraceReader(object):
  class BadTraceException(Exception):
      pass
  
  def __init__(self, tracefile, readahead = 3):
    self._trace = open(tracefile, 'rb')

    header = self._readpb(Trace_pb2.TraceHeader)
    regmap = self._readpb(Trace_pb2.RegisterMap)

    self._build_register_map(regmap)
      
    self._filo = []
    for i in range(readahead):
      evt = self._readpb(Trace_pb2.TraceEvent)
      self._filo.append(evt)

  def get_register_value(self, name):
    return self._register_state[self._register_name_map[name]]

  def next_instruction(self):
    evt = self._get_next_event()
    self._read_next_register_state(evt)
    return evt

  def done(self):
    return self._instructions_until_end_of_trace() == 0

  def _readpb(self, cls):
    obj = cls()

    try:
      len_str = self._trace.read(8)

      # We are at the end of the trace
      if len(len_str) == 0:
          return None

      to_read = struct.unpack('@Q', len_str)[0]
      obj_str = self._trace.read(to_read)
    except struct.error,e:
      raise TraceReader.BadTraceException(cls.__name__)

    obj.ParseFromString(obj_str)
    return obj

  def _build_register_map(self, pb_regmap):
    self._register_name_map = {}
    self._register_state = {}

    for r in pb_regmap.register_map:
      self._register_name_map[r.register_name] = r.register_number
      self._register_state[r.register_number] = None

  def _get_next_event(self):
    next_event = self._readpb(Trace_pb2.TraceEvent)
    evt = None

    if self._filo:
      evt = self._filo.pop(0)

    if next_event:
      self._filo.append(next_event)

    return evt

  def _read_next_register_state(self, last_event):
    for r in last_event.regs:
      value = r.register_value or 0
      self._register_state[r.register_number] = value

  def _instructions_until_end_of_trace(self):
    return len(self._filo)

