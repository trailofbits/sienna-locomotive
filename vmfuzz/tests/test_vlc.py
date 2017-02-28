import os
from context import vmfuzz
os.chdir('..')

vmfuzz.main("yaml_config\\configVLC.yaml", "yaml_config\\system.yaml",
            "C:\\Users\\monty\\Desktop\\dir\\", 0)
