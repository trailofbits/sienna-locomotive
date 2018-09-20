import datetime
import pkg_resources
import os
import glob
import io

from base64 import b64encode
from jinja2 import Environment, PackageLoader

import sl2.harness.config
from sl2.harness.state import get_target_slug, get_target_dir
from sl2.stats.__main__ import plot_discovered_paths


def main():
    env = Environment(loader=PackageLoader('sl2', 'reporting/templates'))
    template = env.get_template('index.html')

    target_dir = get_target_dir(sl2.harness.config.config)
    found = [int(f.split('Report_v')[1].replace('.html', '')) for f in glob.glob(os.path.join(target_dir, 'Report_v*.html'))]
    revision = 0 if len(found) == 0 else max(found) + 1

    coverage_img = io.BytesIO()
    plt = plot_discovered_paths(get_target_slug(sl2.harness.config.config))
    plt.savefig(coverage_img, format='png', dpi=200)
    coverage_graph = b64encode(coverage_img.getvalue()).decode('utf-8')

    vars = {
        'normalize_css': env.get_template('css/normalize.css').render(),
        'skeleton_css': env.get_template('css/skeleton.css').render(),
        'custom_css': env.get_template('css/sl2.css').render(),
        'logo': env.get_template('images/logo.png.b64').render(),
        'app_name': sl2.harness.config.profile,
        'revision': revision,
        'generated': datetime.datetime.now().isoformat(timespec='minutes'),
        'version': pkg_resources.require("sl2")[0].version,
        'uniq_crash_count': 7,
        'total_crash_count': 42,
        'severe_crash_count': 0,
        'run_count': 100000,
        'cpu_time': 80645,
        'path_count': 1024,
        'coverage_estimate': 42.123456789,
        'coverage_graph': coverage_graph
    }

    fname = os.path.join(target_dir, 'Report_v{}.html'.format(revision))

    with open(fname, 'w') as outfile:
        outfile.write(template.render(**vars))

    print("Written to", fname)
    os.startfile(fname)
