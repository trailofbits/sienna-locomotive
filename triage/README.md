# Crash Triage

## Manticore

A few changes are needed for concrete execution.

In **manticore/core/state.py** comment out the following asserts (around line 93) - 

```python
        assert self.platform.constraints is self.constraints
        assert self.mem.constraints is self.constraints
```

In **manticore/manticore.py** (`makeLinux`) change the lines - 

```python
platform = linux.SLinux(program, argv=argv, envp=env,
                             symbolic_files=symbolic_files)
```

```python
platform = linux.Linux(program, argv=argv, envp=env)
```

In **manticore/core/executor.py** comment out the following line -

```python
    'smem': len(state.platform.current.memory._symbols),
```
