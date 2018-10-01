import datetime
import pkg_resources
import os
import glob
import io

from base64 import b64encode
from jinja2 import Environment, PackageLoader
from shutil import copyfile

import sl2.harness.config
from sl2.harness.state import get_target_slug, get_target_dir
from sl2.stats.__main__ import plot_discovered_paths
from sl2 import db
from sl2.db.crash import Crash
from sl2.db.run_block import RunBlock
from sl2.db.coverage import PathRecord


## Filter that formats floats or ints into strings with commas in the thousands place
def comma_ify(value):
    return "{:,}".format(value)


## Create an HTML report for a given target from the database.
def generate_report(dest=None):
    # Create the template environment
    env = Environment(loader=PackageLoader('sl2', 'reporting/templates'))
    env.filters['comma_ify'] = comma_ify  # Pass in the comma_ify filter so we can use it when rendering
    template = env.get_template('index.html')

    # Look for any existing reports and increment the revision number if necessary
    target_dir = get_target_dir(sl2.harness.config.config)
    found = [int(f.split('Report_v')[1].replace('.html', '')) for f in
             glob.glob(os.path.join(target_dir, 'Report_v*.html'))]
    revision = 0 if len(found) == 0 else max(found) + 1

    # Render the graph of the estimated path coverage and base64 encode it
    slug = get_target_slug(sl2.harness.config.config)
    coverage_img = io.BytesIO()
    plt = plot_discovered_paths(slug)
    plt.savefig(coverage_img, format='png', dpi=200)
    coverage_graph = b64encode(coverage_img.getvalue()).decode('utf-8')

    # Get a current estimate of the path coverage
    num_paths, coverage_estimate = PathRecord.estimate_current_path_coverage(slug)

    # Grab the run blocks and crashes from the database
    session = db.getSession()
    run_blocks = session.query(RunBlock).filter(RunBlock.target_config_slug == slug).all()
    crash_base = session.query(Crash).filter(Crash.target_config_slug == slug)

    # create a big dict with all the environment variables for the template to render
    vars = {
        # Get the css framework and custom styles
        'normalize_css': env.get_template('css/normalize.css').render(),
        'skeleton_css': env.get_template('css/skeleton.css').render(),
        'custom_css': env.get_template('css/sl2.css').render(),
        # Get the base64 encoded logo
        'logo': env.get_template('images/logo.png.b64').render(),
        # Get app metadata
        'app_name': sl2.harness.config.profile,
        'revision': revision,
        'generated': datetime.datetime.now().isoformat(timespec='minutes'),
        'version': pkg_resources.require("sl2")[0].version,
        # Get the count of unique, total, and severe crashes from the database
        'uniq_crash_count': crash_base.distinct(Crash.crashash).group_by(Crash.crashash).count(),
        'total_crash_count': crash_base.count(),
        'severe_crash_count': crash_base.filter(Crash.exploitability != "None",
                                                Crash.exploitability != "Unknown",
                                                Crash.exploitability != "Low").group_by(Crash.crashash).count(),
        # Get the number of runs and time spent
        'run_count': sum(x.runs for x in run_blocks),
        'cpu_time': sum(((block.ended - block.started).total_seconds()) for block in run_blocks),
        # Get the number of paths and coverage
        'path_count': num_paths,
        'coverage_estimate': coverage_estimate * 100,
        'coverage_graph': coverage_graph,
        # Generate a list of the unique crashes
        'crashes': sorted(session.query(Crash)
                          .filter(Crash.target_config_slug == slug)
                          .group_by(Crash.crashash).all(),
                          key=lambda crash: crash.int_exploitability)
    }

    # Write the report to the disk
    fname = os.path.join(target_dir, 'Report_v{}.html'.format(revision))
    with open(fname, 'w') as outfile:
        outfile.write(template.render(**vars))

    # Copy the report to the user-selected output folder (if given)
    if dest is not None:
        if '.html' not in dest:
            dest = os.path.join(dest, 'Report_v{}.html'.format(revision))
        copyfile(fname, dest)
        os.startfile(dest)
    else:
        print("Written to", fname)
        os.startfile(fname)

## Generates a fuzzing report. Takes the `-p` parameter to indicate which config profile to use
def main():
    generate_report()
