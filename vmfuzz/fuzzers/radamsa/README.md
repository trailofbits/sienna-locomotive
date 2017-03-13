Radamsa
=======

**How it works:**

- Radamsa uses ```seed_pattern``` ([user configuration](../../yaml_config/README.md#user-configuration)) to detect inputs file 
- Inputs files must be located in the ```path_radamsa_working_directory``` ([system configuration](../../yaml_config/README.md#system-configuration))
- Generated inputs are named fuzz-%d.extension in the working directory
- Crashing inputs are renamed ```crash-%d.extension``` and are kepts in the working directory
- The results of !exploitable is available in the ```vmfuzz.log``` file
