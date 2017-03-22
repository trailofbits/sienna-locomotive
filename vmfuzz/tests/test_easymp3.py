import os
from context import vmfuzz
os.chdir('..')

system = r"sample\config\system\system.yaml"
program = r"sample\config\program\easyRmtoMP3.yaml"
run = r"sample\config\run\easyRmtoMp3ALL.yaml"

vmfuzz.main(system, program, run, 0)
