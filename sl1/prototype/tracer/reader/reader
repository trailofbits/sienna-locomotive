#!/usr/bin/env python2

import tracer
import sys
import argparse



def main():
  parser = argparse.ArgumentParser(description='Consume an execution trace')
  parser.add_argument('input', type=str, help='path to the recorded trace')
  args = parser.parse_args()

  s = open(args.input, 'r')
  i = 0

  try:
    header = tracer.TraceHeader.from_stream(s)
    regmap = tracer.RegisterMap.from_stream(s)

    state = tracer.ExecutionState(regmap)

    while True:
      i += 1
      evt = tracer.TraceEvent.from_stream(s)
      state.update(evt)

      #state.dump()
  except tracer.EndOfTraceException:
    pass

if __name__ == '__main__':
  main()
