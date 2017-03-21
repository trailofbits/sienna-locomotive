import os
from context import vmfuzz
os.chdir('..')

system = r"sample\config\system\system.yaml"
program = r"sample\config\program\sumatraPDF.yaml"
run = r"sample\config\run\sumatraPDFAll.yaml"

vmfuzz.main(system, program, run, 0)
