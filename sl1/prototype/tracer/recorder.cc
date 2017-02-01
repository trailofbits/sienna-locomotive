
#include "recorder.h"

#include "Trace.pb.h"

void
Recorder::recordState(const State &state)
{
  TraceEvent event;
  event.set_n(_written);
  event.set_instruction(state.instruction.data(), state.instruction.size());
  event.set_status(state.status);

  #define REG(n, a, sz)                            \
  if( state.registerState.a !=                     \
            _previous_state.registerState.a ) {    \
    RegisterDelta *r##n = event.add_regs();            \
    r##n->set_register_number(n);                  \
    r##n->set_register_value(state.registerState.a); \
  }
  #include "regs.inc"
  #undef REG

  _previous_state = state;

  _writeState(event.SerializeAsString());
  _written++;
}

void 
Recorder::_writeState(const std::string &data)
{
  uint64_t len = data.size();

  _outs.write((const char *)&len, sizeof(len));
  _outs.write(data.c_str(), data.size());
}

void
Recorder::_writeHeader()
{
  RegisterMap m;

  #define REG(n, nm, sz) \
    RegisterDescription *r##n = m.add_register_map();\
    r##n->set_register_number(n);\
    r##n->set_register_name(#nm);
  #include "regs.inc"
  #undef REG

  auto header_s = _header.SerializeAsString();
  uint64_t sz = header_s.size();
  _outs.write((char *)&sz, sizeof(sz));
  _outs.write(header_s.c_str(), sz);

  //_outs = std::ofstream(path);
  auto m_s = m.SerializeAsString();

  sz = m_s.size();
  _outs.write((char *)&sz, sizeof(sz));
  _outs.write(m_s.c_str(), sz);
  _outs.flush();
}
