import os
from context import vmfuzz
os.chdir('..')

system = r"sample\config\system\system.yaml"
program = r"sample\config\program\vlc.yaml"
run = r"sample\config\run\vlcAll.yaml"

vmfuzz.main(system, program, run, 0)
