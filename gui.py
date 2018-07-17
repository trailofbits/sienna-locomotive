import sys

from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFontDatabase, QMovie

from gui.checkbox_tree import CheckboxTreeWidget, CheckboxTreeWidgetItem
from gui.QtHelpers import QIntVariable, QFloatVariable, QTextAdapter

from harness import config
from harness.state import get_target
from harness.threads import WizardThread, FuzzerThread
from functools import partial


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)

        self.setWindowTitle("Sienna Locomotive 2")
        self.setMinimumSize(QSize(1300, 800))

        self.get_config()

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)

        self._layout = QtWidgets.QGridLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        self.wizard_run = QtWidgets.QPushButton("Run Wizard")
        self.wizard_thread = WizardThread(config.config)
        self.wizard_thread.resultReady.connect(self.wizard_finished)
        self.wizard_run.clicked.connect(self.wizard_thread.start)
        self.wizard_thread.started.connect(partial(self.setCursor, Qt.WaitCursor))
        self.wizard_thread.finished.connect(self.unsetCursor)
        self._layout.addWidget(self.wizard_run)

        self.target_data = get_target(config.config)
        self._func_tree = CheckboxTreeWidget()
        self._layout.addWidget(self._func_tree)
        self._func_tree.itemCheckedStateChanged.connect(self.tree_changed)

        self.build_func_tree()

        self.fuzzer_run = QtWidgets.QPushButton("Fuzz selected targets")
        self._layout.addWidget(self.fuzzer_run)

        self._stateDisplay = QtWidgets.QTextBrowser()
        self._stateDisplay.setOpenLinks(False)
        self._stateDisplay.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self._layout.addWidget(self._stateDisplay)

        self.fuzzer_thread = FuzzerThread(config.config, self.target_data.filename)
        self.fuzzer_thread.foundCrash.connect(self._stateDisplay.append)
        self.fuzzer_run.clicked.connect(self.fuzzer_thread.start)

        self.stop_button = QtWidgets.QPushButton("Stop Fuzzing")
        self.stop_button.hide()
        self._layout.addWidget(self.stop_button)

        self.stop_button.clicked.connect(self.fuzzer_thread.pause)
        if config.config['continuous']:
            self.fuzzer_thread.started.connect(self.stop_button.show)
        self.fuzzer_thread.finished.connect(self.stop_button.hide)
        self.fuzzer_thread.paused.connect(self.stop_button.hide)

        self._status_bar = QtWidgets.QStatusBar()
        self._layout.addWidget(self._status_bar)

        self.runs, self.crashes = QIntVariable(0), QIntVariable(0)
        self.throughput = QFloatVariable(0.0)
        self.run_adapter = QTextAdapter("Fuzzing Runs: {0.value} ", self.runs)
        self.throughput_adapter = QTextAdapter(" {0.value:.3f} Runs/s: ", self.throughput)
        self.crash_adapter = QTextAdapter(" Crashes Found: {0.value} ", self.crashes)
        self.runs.valueChanged.connect(self.run_adapter.update)
        self.throughput.valueChanged.connect(self.throughput_adapter.update)
        self.crashes.valueChanged.connect(self.crash_adapter.update)

        self.busy_label = QtWidgets.QLabel()
        busy_gif = QMovie("gui/busy.gif")
        self.busy_label.setMovie(busy_gif)
        busy_gif.start()
        self.busy_label.hide()

        self.fuzz_count = QtWidgets.QLabel()
        self.throughput_label = QtWidgets.QLabel()
        self.crash_count = QtWidgets.QLabel()

        self.run_adapter.updated.connect(self.fuzz_count.setText)
        self.throughput_adapter.updated.connect(self.throughput_label.setText)
        self.crash_adapter.updated.connect(self.crash_count.setText)

        self.fuzzer_thread.runComplete.connect(self.runs.increment)
        self.fuzzer_thread.runComplete.connect(self.calculate_throughput)
        self.fuzzer_thread.foundCrash.connect(self.crashes.increment)

        self.fuzzer_thread.started.connect(self.busy_label.show)
        self.fuzzer_thread.finished.connect(self.busy_label.hide)

        self._status_bar.addWidget(self.busy_label)
        self._status_bar.addWidget(self.fuzz_count)
        self._status_bar.addWidget(self.throughput_label)
        self._status_bar.addWidget(self.crash_count)

    def calculate_throughput(self, total_time):
        self.throughput.update(self.runs.value / total_time)

    def build_func_tree(self):
        self._func_tree.clear()

        for index, option in enumerate(self.target_data):
            widget = CheckboxTreeWidgetItem(self._func_tree, index)
            widget.setText(0, ("{func_name} from {source}:{start}-{end}" if 'source' in option
                               else "{func_name}").format(**option))
            widget.setCheckState(0, Qt.Checked if option["selected"] else Qt.Unchecked)

            for address in range(0, min(len(option["buffer"]), 16*5), 16):
                hexstr = " ".join("{:02X}".format(c) for c in option["buffer"][address:address + 16])
                asciistr = "".join((chr(c) if c in range(31, 127) else '.') for c in option["buffer"][address:address + 16])
                formatted = "0x%04X:  %s  | %s" % (address, hexstr + " " * (16 * 3 - len(hexstr)), asciistr)
                data_disp = CheckboxTreeWidgetItem(widget, 0, is_checkbox=False)
                data_disp.setText(0, formatted)
                data_disp.setFont(0, QFontDatabase.systemFont(QFontDatabase.FixedFont))

            self._func_tree.insertTopLevelItem(0, widget)

    def tree_changed(self, widget, _column, is_checked):
        self.target_data.update(widget.index, selected=is_checked)

    def wizard_finished(self, wizard_output):
        self.target_data.set_target_list(wizard_output)
        self.build_func_tree()

    def get_config(self):
        """ Selects the configuration dict from config.py """
        profile, cont = QtWidgets.QInputDialog.getItem(self,
                                                       "Select Configuration Profile",
                                                       "Select Configuration Profile",
                                                       config._config.keys(),
                                                       0, False)
        if cont:
            config.set_profile(profile)
        else:
            exit(0)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())
