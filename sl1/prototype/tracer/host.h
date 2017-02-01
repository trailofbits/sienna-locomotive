
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#pragma once

class OSTraceSupport {
public:
  virtual ~OSTraceSupport(){}

  void setPid(pid_t pid) { _pid = pid; }
  virtual long waitUntilExec() = 0;
  virtual void traceMe() = 0;
  virtual void step() = 0;
  virtual void getRegisters(void *dest) = 0;
  virtual long peekText(uint64_t addr) = 0;
  virtual long peekData(uint64_t addr) = 0;

protected:
  pid_t _pid;
};

class LinuxHostSupport : public OSTraceSupport {
public:
  virtual void traceMe() override {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  }
  virtual void step() override {
    ptrace(PTRACE_SINGLESTEP, _pid, NULL, NULL);
  }

  virtual void getRegisters(void *dest) override {
    ptrace(PTRACE_GETREGS, _pid, NULL, (struct user_regs_struct *)dest);
  }

  virtual long peekText(uint64_t addr) override {
    return ptrace(PTRACE_PEEKTEXT, _pid, (caddr_t)addr, NULL);
  }

  virtual long peekData(uint64_t addr) override {
    return ptrace(PTRACE_PEEKDATA, _pid, (caddr_t)addr, NULL);
  }

  virtual long waitUntilExec() override {
    int status;

    ptrace(PTRACE_SETOPTIONS, _pid, PTRACE_O_TRACEEXEC|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK, NULL);

    waitpid(_pid, &status, 0);

    return 0;
  }
};