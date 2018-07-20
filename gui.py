import sys

from PyQt5.QtWidgets import QFileDialog
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QSize, QSortFilterProxyModel
from PyQt5.QtGui import QFontDatabase, QMovie, QStandardItem

from gui.checkbox_tree import CheckboxTreeWidget, CheckboxTreeWidgetItem, CheckboxTreeModel
from gui.QtHelpers import QIntVariable, QFloatVariable, QTextAdapter

from harness import config
from harness.state import get_target, export_crash_data_to_csv
from harness.threads import WizardThread, FuzzerThread
from functools import partial


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.crashes = []

        # Select config profile before starting
        self.get_config()

        # Set up basic window
        self.setWindowTitle("Sienna Locomotive 2")
        self.setMinimumSize(QSize(1600, 1200))

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)
        self._layout = QtWidgets.QVBoxLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        # CREATE WIDGETS #

        # Set up Wizard thread and button
        self.wizard_thread = WizardThread(config.config)

        self.wizard_button = QtWidgets.QPushButton("Run Wizard")
        self._layout.addWidget(self.wizard_button)

        # Set up function tree display
        self._func_tree = CheckboxTreeWidget()
        self._layout.addWidget(self._func_tree)

        # Set up underlying model for exposing function data
        self.target_data = get_target(config.config)
        self.model = CheckboxTreeModel()
        self.func_proxy_model = QSortFilterProxyModel()
        self.func_proxy_model.setSourceModel(self.model)
        self.func_proxy_model.setFilterKeyColumn(0)
        self.file_proxy_model = QSortFilterProxyModel()
        self.file_proxy_model.setSourceModel(self.func_proxy_model)
        self.file_proxy_model.setFilterKeyColumn(1)
        self.build_func_tree()
        self._func_tree.setModel(self.file_proxy_model)

        # These need to happen after we set the model
        self._func_tree.expandAll()
        self._func_tree.resizeColumnToContents(0)
        self._func_tree.resizeColumnToContents(1)
        self._func_tree.resizeColumnToContents(2)
        self._func_tree.resizeColumnToContents(3)

        # Build layout for function filter text boxes
        self.filter_layout = QtWidgets.QHBoxLayout()
        self.filter_layout.addWidget(QtWidgets.QLabel("Filter Function: "))
        self.func_filter_box = QtWidgets.QLineEdit()
        self.filter_layout.addWidget(self.func_filter_box)
        self.filter_layout.addWidget(QtWidgets.QLabel("Filter Files: "))
        self.file_filter_box = QtWidgets.QLineEdit()
        self.filter_layout.addWidget(self.file_filter_box)

        self._layout.addLayout(self.filter_layout)

        # Set up fuzzer button and thread
        self.fuzzer_button = QtWidgets.QPushButton("Fuzz selected targets")
        self._layout.addWidget(self.fuzzer_button)

        self.fuzzer_thread = FuzzerThread(config.config, self.target_data.filename)

        # Set up text window displaying triage output
        self.triage_output = QtWidgets.QTextBrowser()
        self.triage_output.setOpenLinks(False)
        self.triage_output.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self._layout.addWidget(self.triage_output)

        # Set up stop button (and hide it)
        self.stop_button = QtWidgets.QPushButton("Stop Fuzzing")
        self.stop_button.hide()
        self._layout.addWidget(self.stop_button)

        self.save_button = QtWidgets.QPushButton("Save Triage Results")
        self._layout.addWidget(self.save_button)

        # Set up status bar
        self.status_bar = QtWidgets.QStatusBar()
        self._layout.addWidget(self.status_bar)

        # Create helper variables for storing counters with signals attached
        self.runs, self.crash_counter = QIntVariable(0), QIntVariable(0)
        self.throughput = QFloatVariable(0.0)
        self.run_adapter = QTextAdapter("Fuzzing Runs: {0.value} ", self.runs)
        self.throughput_adapter = QTextAdapter(" {0.value:.3f} Runs/s ", self.throughput)
        self.crash_adapter = QTextAdapter(" Crashes Found: {0.value} ", self.crash_counter)

        # Create the busy label
        self.busy_label = QtWidgets.QLabel()
        busy_gif = QMovie("gui/busy.gif")
        self.busy_label.setMovie(busy_gif)
        busy_gif.start()
        self.busy_label.hide()

        # Set up labels for the status bar
        self.fuzz_count = QtWidgets.QLabel()
        self.throughput_label = QtWidgets.QLabel()
        self.crash_count = QtWidgets.QLabel()

        # Add all the labels to the status bar
        self.status_bar.addPermanentWidget(self.busy_label)
        self.status_bar.addWidget(self.fuzz_count)
        self.status_bar.addWidget(self.throughput_label)
        self.status_bar.addWidget(self.crash_count)

        # CONNECT SIGNALS #

        # Update the text of the status bar adapters whenever the underlying variables change
        self.runs.valueChanged.connect(self.run_adapter.update)
        self.throughput.valueChanged.connect(self.throughput_adapter.update)
        self.crash_counter.valueChanged.connect(self.crash_adapter.update)

        self.run_adapter.updated.connect(self.fuzz_count.setText)
        self.throughput_adapter.updated.connect(self.throughput_label.setText)
        self.crash_adapter.updated.connect(self.crash_count.setText)

        # Update the run/crash/throughput variables after every fuzzing run
        self.fuzzer_thread.runComplete.connect(self.runs.increment)
        self.fuzzer_thread.runComplete.connect(self.calculate_throughput)
        self.fuzzer_thread.foundCrash.connect(self.crash_counter.increment)

        # Show the busy symbol while we're fuzzing and hide it while we're not
        self.fuzzer_thread.started.connect(self.busy_label.show)
        self.fuzzer_thread.finished.connect(self.busy_label.hide)

        # Start the wizard when we click the button and update the tree when we're done
        self.wizard_button.clicked.connect(self.wizard_thread.start)
        self.wizard_thread.started.connect(partial(self.setCursor, Qt.WaitCursor))
        self.wizard_thread.finished.connect(self.unsetCursor)
        self.wizard_thread.resultReady.connect(self.wizard_finished)

        # Filter the list of functions displayed when we type things into the boxes
        self.func_filter_box.textChanged.connect(self.func_proxy_model.setFilterFixedString)
        self.file_filter_box.textChanged.connect(self.file_proxy_model.setFilterFixedString)

        # Handle checks/unchecks in the target tree
        self._func_tree.itemCheckedStateChanged.connect(self.tree_changed)

        # Start the fuzzer and display triage output
        self.fuzzer_thread.foundCrash.connect(self.handle_new_crash)
        self.fuzzer_button.clicked.connect(self.fuzzer_thread.start)
        self.save_button.clicked.connect(self.save_crashes)

        # Connect the stop button to the thread so we can pause it
        self.stop_button.clicked.connect(self.fuzzer_thread.pause)
        if config.config['continuous']:
            self.fuzzer_thread.started.connect(self.stop_button.show)
        self.fuzzer_thread.finished.connect(self.stop_button.hide)
        self.fuzzer_thread.paused.connect(self.stop_button.hide)

    def calculate_throughput(self, total_time):
        """ Calculate our current runs/second. TODO: make this a lambda? """
        self.throughput.update(self.runs.value / total_time)

    def build_func_tree(self):
        """ Build the function target display tree """
        self._func_tree.setSortingEnabled(False)
        self.model.clear()
        self.model.setHorizontalHeaderLabels(["Function Name", "File", "File Offset", "Order Seen", "Binary Offset"])
        self.model.horizontalHeaderItem(0).setToolTip("The name of a fuzzable function")
        self.model.horizontalHeaderItem(1).setToolTip("The name of the file (if any) the function tried to read")
        self.model.horizontalHeaderItem(2).setToolTip("The bytes in the file that the program tried to read (if available)")
        self.model.horizontalHeaderItem(3).setToolTip("The order in which the wizard encountered this function")
        self.model.horizontalHeaderItem(4).setToolTip("How far (in memory) away from the start of the target program the call to this function occurred. Lower values are usually better targets.")

        for index, option in enumerate(self.target_data):
            funcname_widget = CheckboxTreeWidgetItem(self._func_tree, index, "{func_name}".format(**option))
            filename_widget = QStandardItem(option.get('source', None))
            offset_widget = QStandardItem("0x{:x} - 0x{:x}".format(option['start'], option['end'])
                                          if ('end' in option and 'start' in option)
                                          else None)
            funcname_widget.setCheckState(Qt.Checked if option["selected"] else Qt.Unchecked)
            funcname_widget.setColumnCount(3)

            add = []
            hx = []
            asc = []
            for address in range(0, min(len(option["buffer"]), 16*5), 16):
                add.append("0x%04X" % address)
                hx.append(" ".join("{:02X}".format(c) for c in option["buffer"][address:address + 16]))
                asc.append("".join((chr(c) if c in range(31, 127) else '.') for c in option["buffer"][address:address + 16]))
            addr = QStandardItem('\n'.join(add))
            hexstr = QStandardItem('\n'.join(hx))
            asciistr = QStandardItem('\n'.join(asc))
            addr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            hexstr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            asciistr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            funcname_widget.appendRow([addr, hexstr, asciistr])

            self.model.appendRow([funcname_widget,
                                  filename_widget,
                                  offset_widget,
                                  QStandardItem(str(index)),
                                  QStandardItem(str(option.get('retAddrOffset', None)))])

        self._func_tree.expandAll()
        self._func_tree.resizeColumnToContents(0)
        self._func_tree.resizeColumnToContents(1)
        self._func_tree.resizeColumnToContents(2)
        self._func_tree.resizeColumnToContents(3)

        self._func_tree.sortByColumn(3, Qt.AscendingOrder)
        self._func_tree.setSortingEnabled(True)

    def tree_changed(self, widget, is_checked):
        """ Handle when an item in the function tree is checked """
        self.target_data.update(widget.index, selected=is_checked)

    def wizard_finished(self, wizard_output):
        """ Dump the results of a wizard run to the target file and rebuild the tree """
        self.target_data.set_target_list(wizard_output)
        self.build_func_tree()

    def handle_new_crash(self, formatted, crash):
        self.triage_output.append(formatted)
        self.crashes.append(crash)

    def save_crashes(self):
        saveFile = QFileDialog.getSaveFileName(self, filter="*.csv")
        export_crash_data_to_csv(self.crashes, saveFile[0])

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

    try:
        import qdarkstyle
        app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    except ImportError:
        pass

    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())
