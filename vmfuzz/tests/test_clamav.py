import os
from context import vmfuzz
os.chdir('..')

system = r"sample\config\system\system.yaml"
program = r"sample\config\program\clamav.yaml"
run = r"sample\config\run\clamavAll.yaml"

vmfuzz.main(system, program, run, 0)
