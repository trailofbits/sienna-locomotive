import os
from context import vmfuzz
import exploitability.exploitable_standalone as exploitable_standalone
os.chdir('..')

vmfuzz.main("yaml_config\\configSumatraPDF.yaml",
            "yaml_config\\system.yaml",0)
