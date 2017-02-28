import os
from context import vmfuzz
os.chdir('..')
vmfuzz.main("yaml_config\\configEasyRmtoMP3.yaml",
            "yaml_config\\system.yaml", "C:\\Users\\monty\\Desktop\\dir\\", 1)
