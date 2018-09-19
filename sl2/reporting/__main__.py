import matplotlib.pyplot as plt
import statistics

from sl2 import db
from sl2.db.run_block import RunBlock
from sl2.harness import config
from sl2.gui.config_window import ConfigWindow
from PySide2 import QtWidgets
from sl2.harness.state import get_target_slug

from jinja2 import Environment, PackageLoader


def main():
    env = Environment(loader=PackageLoader('sl2', 'reporting/templates'))
    template = env.get_template('index.html')

    vars = {
        'app_name': 'PEParse',
        'run_count': 100000,
        'cpu_time': 80645,
    }

    print(template.render(**vars))
