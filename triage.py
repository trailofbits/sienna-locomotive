import glob
import os
import harness.config
import subprocess
def main():
    cfg = harness.config
    runsglob = os.path.join( harness.config.sl2_runs_dir, '*', '*.dmp' )
    print(runsglob)
    paths = glob.glob( runsglob )
    for path in paths:
        cmd = [ cfg.config['triager_path'], path ]
        print("$ ", cmd )
        out = subprocess.check_output(cmd, shell=False)
        print("# ", out )
    print(cfg.config)

if __name__ == '__main__':
    main()
