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


def comma_ify(value):
    return "{:,}".format(value)


def generate_report(dest=None):
    env = Environment(loader=PackageLoader('sl2', 'reporting/templates'))
    env.filters['comma_ify'] = comma_ify
    template = env.get_template('index.html')

    target_dir = get_target_dir(sl2.harness.config.config)
    found = [int(f.split('Report_v')[1].replace('.html', '')) for f in
             glob.glob(os.path.join(target_dir, 'Report_v*.html'))]
    revision = 0 if len(found) == 0 else max(found) + 1

    slug = get_target_slug(sl2.harness.config.config)
    coverage_img = io.BytesIO()
    plt = plot_discovered_paths(slug)
    plt.savefig(coverage_img, format='png', dpi=200)
    coverage_graph = b64encode(coverage_img.getvalue()).decode('utf-8')

    num_paths, coverage_estimate = PathRecord.estimate_current_path_coverage(slug)

    session = db.getSession()
    run_blocks = session.query(RunBlock).filter(RunBlock.target_config_slug == slug).all()
    crash_base = session.query(Crash).filter(Crash.target_config_slug == slug)

    vars = {
        'normalize_css': env.get_template('css/normalize.css').render(),
        'skeleton_css': env.get_template('css/skeleton.css').render(),
        'custom_css': env.get_template('css/sl2.css').render(),
        'logo': env.get_template('images/logo.png.b64').render(),
        'app_name': sl2.harness.config.profile,
        'revision': revision,
        'generated': datetime.datetime.now().isoformat(timespec='minutes'),
        'version': pkg_resources.require("sl2")[0].version,
        'uniq_crash_count': crash_base.distinct(Crash.crashash).group_by(Crash.crashash).count(),
        'total_crash_count': crash_base.count(),
        'severe_crash_count': crash_base.filter(Crash.exploitability != "None",
                                                Crash.exploitability != "Unknown",
                                                Crash.exploitability != "Low").group_by(Crash.crashash).count(),
        'run_count': sum(x.runs for x in run_blocks),
        'cpu_time': sum(((block.ended - block.started).total_seconds()) for block in run_blocks),
        'path_count': num_paths,
        'coverage_estimate': coverage_estimate * 100,
        'coverage_graph': coverage_graph,
        'crashes': sorted(session.query(Crash)
                          .filter(Crash.target_config_slug == slug)
                          .group_by(Crash.crashash).all(),
                          key=lambda crash: crash.int_exploitability)
    }

    fname = os.path.join(target_dir, 'Report_v{}.html'.format(revision))

    with open(fname, 'w') as outfile:
        outfile.write(template.render(**vars))

    if dest is not None:
        if '.html' not in dest:
            dest = os.path.join(dest, 'Report_v{}.html'.format(revision))
        copyfile(fname, dest)
        os.startfile(dest)
    else:
        print("Written to", fname)
        os.startfile(fname)


def main():
    generate_report()
