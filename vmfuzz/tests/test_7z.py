import os
from context import vmfuzz
os.chdir('..')

vmfuzz.main("yaml_config\\config7zip.yaml", "yaml_config\\system.yaml", 0)
