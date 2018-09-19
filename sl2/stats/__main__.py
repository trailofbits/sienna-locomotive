import matplotlib.pyplot as plt

from sl2 import db
from sl2.db.run_block import RunBlock
from sl2.harness import config
from sl2.gui.config_window import ConfigWindow
from PySide2 import QtWidgets
from sl2.harness.state import get_target_slug


def get_fuzzing_time(run_blocks):
    out = []
    total_time_spent_fuzzing = 0
    for block in run_blocks:
        total_time_spent_fuzzing += (block.ended - block.started).total_seconds()
        out.append(total_time_spent_fuzzing)
    return out


def plot_run_rate(target_slug):
    session = db.getSession()
    target_runs = session.query(RunBlock).filter(RunBlock.target_config_slug == target_slug).all()

    rates = []
    for block in target_runs:
        elapsed = block.ended - block.started
        rate = block.runs / elapsed.total_seconds()
        rates.append(rate)

    plt.plot(get_fuzzing_time(target_runs), rates, marker='o')
    plt.xlabel("Seconds spent fuzzing")
    plt.ylabel("Runs/Second (single threaded)")
    plt.show()


def plot_discovered_paths(target_slug):
    session = db.getSession()
    target_runs = session.query(RunBlock).filter(RunBlock.target_config_slug == target_slug).all()

    figure, count = plt.subplots()

    count.plot(get_fuzzing_time(target_runs), [block.num_paths for block in target_runs], marker='o')
    count.set_xlabel("Seconds spent fuzzing")
    count.set_ylabel("Unique Paths Encountered")

    percentage = count.twinx()
    percentage.plot(get_fuzzing_time(target_runs), [(block.path_coverage * 100) for block in target_runs], marker=',', color='r')
    percentage.set_ylabel("Estimated path completion percentage")

    figure.tight_layout()
    plt.show()


def main():
    app = QtWidgets.QApplication([])

    cfg = ConfigWindow()
    if cfg.exec() == QtWidgets.QDialog.Rejected:
        return

    slug = get_target_slug(config.config)
    print("Getting stats for", slug)

    plot_run_rate(slug)
    plot_discovered_paths(slug)

