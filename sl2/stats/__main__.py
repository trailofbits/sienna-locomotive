import matplotlib.pyplot as plt
import statistics

from sl2 import db
from sl2.db.run_block import RunBlock
from sl2.harness import config
from sl2.harness.state import get_target_slug

## Gets a list of the total number of CPU seconds spent fuzzing after each block
# @param run_blocks: List[RunBlock] - A list of run blocks
# @return timing: List[int] - strictly increasing list of number of seconds spent after each block
def get_fuzzing_time(run_blocks):
    out = []
    total_time_spent_fuzzing = 0
    for block in run_blocks:
        total_time_spent_fuzzing += (block.ended - block.started).total_seconds()
        out.append(total_time_spent_fuzzing)
    return out


## Builds a plot of the runs/sec/cpu over time
#  @param target_slug - the target to build the graph for
def plot_run_rate(target_slug):
    session = db.getSession()
    target_runs = session.query(RunBlock).filter(RunBlock.target_config_slug == target_slug).all()

    rates = []
    for block in target_runs:
        elapsed = block.ended - block.started
        rate = block.runs / elapsed.total_seconds()
        rates.append(rate)

    stddev = statistics.stdev(rates)
    mean = statistics.mean(rates)

    no_outliers = list(filter(lambda x: abs(x[0] - mean) < 4*stddev, zip(rates, target_runs)))


    plt.plot(get_fuzzing_time(k[1] for k in no_outliers), [k[0] for k in no_outliers], marker='o')
    plt.xlabel("Seconds spent fuzzing")
    plt.ylabel("Runs/Second (single threaded)")
    return plt


## Builds a graph of the number of discovered paths and estimated path coverage over time
#  @param target_slug - the target to build the graph for
def plot_discovered_paths(target_slug):
    session = db.getSession()
    target_runs = session.query(RunBlock).filter(RunBlock.target_config_slug == target_slug).all()

    figure, count = plt.subplots()

    # Plot the number of paths over time
    count.plot(get_fuzzing_time(target_runs), [block.num_paths for block in target_runs], marker='.', color='black')
    count.set_xlabel("Seconds spent fuzzing")
    count.set_ylabel("Unique Paths Encountered")
    count.legend(['Unique Paths'])

    # Plot the estimated percentage of all paths over time
    percentage = count.twinx()
    percentage.plot(get_fuzzing_time(target_runs), [(block.path_coverage * 100) for block in target_runs], marker=',', color='r')
    percentage.legend(['Estimated Completion'])
    percentage.set_ylabel("Estimated path completion percentage")

    plt.title("Code Paths Over Time")
    figure.tight_layout()
    return plt


## Builds and renders rate/time graph and path graph
def main():
    slug = get_target_slug(config.config)
    print("Getting stats for", slug)

    plot_run_rate(slug)
    # plt.show()
    plot_discovered_paths(slug)
    plt.show()

