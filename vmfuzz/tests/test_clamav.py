import os
from context import vmfuzz
os.chdir('..')

vmfuzz.main("yaml_config\\configClamAV.yaml",
            "yaml_config\\system.yaml",0)
