
namespace  google_breakpad {
    void PrintProcessStateMachineReadable(const ProcessState& process_state);
    void PrintProcessState(const ProcessState& process_state,
                        bool output_stack_contents,
                        SourceLineResolverInterface* resolver);
}

