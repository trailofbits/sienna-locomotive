Fuzzers
======
Available fuzzers:
- Winafl ([doc](winafl/README.md))
- Radamsa ([doc](radamsa/README.md))



Minimal example:
```python
import fuzzers.fuzzer as fuzzer # fuzzer is either winafl or radamsa
import utils.parsing_conf as parsing_conf

config_system = parsing_conf.parse_conf("system.yaml")
config = parsing_conf.parse_conf("program.yaml")

parsing_config.check_system_config(config_system)
parsing_config.check_user_config(config)

fuzzer.init(config_system)
fuzzer.launch_fuzzing(config)
```
