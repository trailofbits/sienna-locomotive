######################################################
## @package gui
# Code for the QT gui

import os
import sys
import time
from functools import partial
from multiprocessing import cpu_count

from PySide2 import QtWidgets
from PySide2.QtCore import *
from PySide2.QtGui import QFontDatabase, QMovie, QStandardItem, QBrush, QColor
from PySide2.QtWidgets import *
from sqlalchemy import desc

from sl2 import db
from . import stats
import triage
from .config_window import ConfigWindow
from . import sqlalchemy_model
from .QtHelpers import QIntVariable, QFloatVariable, QTextAdapter
from .checkbox_tree import (
    CheckboxTreeWidget,
    CheckboxTreeWidgetItem,
    CheckboxTreeModel,
    CheckboxTreeSortFilterProxyModel,
    ComboboxTreeItemDelegate,
    mode_labels)
from sl2.harness import config
from sl2.harness.state import get_target, export_crash_data_to_csv, get_target_slug
from sl2.harness.threads import ChecksecThread, WizardThread, FuzzerThread, ServerThread


##
# Main window for gui
class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.crashes = []
        self.thread_holder = []
        self.start_time = None

        # Select config profile before starting
        self.cfg = ConfigWindow()
        self.cfg.exec()

        # Set up basic window
        self.setWindowTitle("Sienna Locomotive 2")
        self.setMinimumSize(QSize(1800, 1300))

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)
        self._layout = QtWidgets.QVBoxLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        # Set up Checksec, Wizard and Server threads so we don't block the UI
        # when they're running
        self.checksec_thread = ChecksecThread(config.config['target_application_path'])
        self.wizard_thread = WizardThread(config.config)
        self.server_thread = ServerThread()

        # CREATE WIDGETS #

        # Target info
        self.targetStatus = QtWidgets.QStatusBar()
        self.targetLabel = QtWidgets.QLabel()
        self.targetStatus.addWidget(self.targetLabel)
        self._layout.addWidget(self.targetStatus)

        self.checksec_thread.start()
        self.checksec_thread.resultReady.connect(self.checksec_finished)

        # Create wizard button
        self.wizard_button = QtWidgets.QPushButton("Run Wizard")
        self._layout.addWidget(self.wizard_button)

        # Set up function tree display
        self._func_tree = CheckboxTreeWidget()
        self._layout.addWidget(self._func_tree)

        # Set up underlying model for exposing function data
        self.target_data = get_target(config.config)
        self.model = CheckboxTreeModel()
        self.func_proxy_model = CheckboxTreeSortFilterProxyModel()
        self.func_proxy_model.setSourceModel(self.model)
        self.func_proxy_model.setFilterKeyColumn(0)
        self.file_proxy_model = CheckboxTreeSortFilterProxyModel()
        self.file_proxy_model.setSourceModel(self.func_proxy_model)
        self.file_proxy_model.setFilterKeyColumn(1)
        self.module_proxy_model = CheckboxTreeSortFilterProxyModel()
        self.module_proxy_model.setSourceModel(self.file_proxy_model)
        self.module_proxy_model.setFilterKeyColumn(4)
        self.build_func_tree()
        self._func_tree.setModel(self.module_proxy_model)
        self._func_tree.setItemDelegate(ComboboxTreeItemDelegate(self.target_data))

        # These need to happen after we set the model
        self._func_tree.expandAll()
        self._func_tree.resizeColumnToContents(0)
        self._func_tree.resizeColumnToContents(1)
        self._func_tree.resizeColumnToContents(2)
        self._func_tree.resizeColumnToContents(3)

        # Create menu items for the context menu
        self.expand_action = QAction("Expand All")
        self.collapse_action = QAction("Collapse All")
        self.check_action = QAction("Check All")
        self.uncheck_action = QAction("Uncheck All")

        # Build layout for function filter text boxes
        self.filter_layout = QtWidgets.QHBoxLayout()
        self.filter_layout.addWidget(QtWidgets.QLabel("Filter Function: "))
        self.func_filter_box = QtWidgets.QLineEdit()
        self.filter_layout.addWidget(self.func_filter_box)
        self.filter_layout.addWidget(QtWidgets.QLabel("Filter Files: "))
        self.file_filter_box = QtWidgets.QLineEdit()
        self.filter_layout.addWidget(self.file_filter_box)
        self.filter_layout.addWidget(QtWidgets.QLabel("Filter Modules: "))
        self.module_filter_box = QtWidgets.QLineEdit()
        self.filter_layout.addWidget(self.module_filter_box)

        # Set up fuzzer button
        self.fuzzer_button = QtWidgets.QPushButton("Fuzz selected targets")

        # Create checkboxes for continuous mode
        self.continuous_mode_cbox = QtWidgets.QCheckBox("Continuous")
        self.pause_mode_cbox = QtWidgets.QCheckBox("Pause on crash")
        if config.config['continuous']:
            self.continuous_mode_cbox.setChecked(True)
        if config.config['exit_early']:
            self.pause_mode_cbox.setChecked(True)

        # Set up spinboxes for setting timeout values
        self.fuzz_timeout_box = QtWidgets.QSpinBox()
        self.fuzz_timeout_box.setSuffix(" seconds")
        self.fuzz_timeout_box.setMaximum(1200)
        if 'fuzz_timeout' in config.config:
            self.fuzz_timeout_box.setValue(config.config['fuzz_timeout'])
        self.fuzz_timeout_box.setSpecialValueText("None")
        self.tracer_timeout_box = QtWidgets.QSpinBox()
        self.tracer_timeout_box.setSuffix(" seconds")
        self.tracer_timeout_box.setMaximum(2400)
        if 'tracer_timeout' in config.config:
            self.tracer_timeout_box.setValue(config.config['tracer_timeout'])
        self.tracer_timeout_box.setSpecialValueText("None")
        self.tracer_timeout_box.setSingleStep(10)
        self.verboseCheckBox = QtWidgets.QCheckBox()
        self.verboseCheckBox.clicked.connect(self.verboseCheckBox_clicked)

        # Create spinbox for controlling simultaneous fuzzing instances
        self.thread_count = QtWidgets.QSpinBox()
        self.thread_count.setSuffix(" threads")
        self.thread_count.setRange(1, 2 * cpu_count())
        if 'simultaneous' in config.config:
            self.thread_count.setValue(config.config['simultaneous'])

        # Create button for hiding and showing the extended controls
        self.expand_button = QtWidgets.QToolButton()
        self.expand_button.setArrowType(Qt.DownArrow)

        # Create nested widget to hold the expanded fuzzing controls
        self.extension_widget = QtWidgets.QWidget()
        self.extension_layout = QtWidgets.QGridLayout()
        self.extension_widget.setLayout(self.extension_layout)

        # Create layouts for fuzzing controls
        self.fuzz_controls_outer_layout = QtWidgets.QHBoxLayout()
        self.fuzz_controls_inner_left = QtWidgets.QVBoxLayout()
        self.fuzz_controls_inner_right = QtWidgets.QVBoxLayout()

        # Add widgets to left, right, and expanded layouts
        self.fuzz_controls_inner_left.addLayout(self.filter_layout)
        self.fuzz_controls_inner_left.addWidget(self.extension_widget)
        self.extension_widget.hide()
        self.fuzz_controls_inner_left.addWidget(self.fuzzer_button)
        self.extension_layout.addWidget(self.continuous_mode_cbox, 0, 0)
        self.extension_layout.addWidget(self.pause_mode_cbox, 1, 0)
        self.extension_layout.addWidget(QtWidgets.QLabel("Fuzz timeout:"), 0, 1, 1, 1, Qt.AlignRight)
        self.extension_layout.addWidget(self.fuzz_timeout_box, 0, 2, 1, 1, Qt.AlignLeft)
        self.extension_layout.addWidget(QtWidgets.QLabel("Triage Timeout:"), 1, 1, 1, 1, Qt.AlignRight)
        self.extension_layout.addWidget(self.tracer_timeout_box, 1, 2, 1, 1, Qt.AlignLeft)
        self.extension_layout.addWidget(QtWidgets.QLabel("Simultaneous fuzzing threads:"), 0, 3, 1, 1, Qt.AlignRight)
        self.extension_layout.addWidget(self.thread_count, 0, 4, 1, 1, Qt.AlignLeft)

        self.extension_layout.addWidget(QtWidgets.QLabel("Verbose:"), 1, 3, 1, 1, Qt.AlignRight)
        self.extension_layout.addWidget(self.verboseCheckBox, 1, 4, 1, 1, Qt.AlignLeft)

        self.fuzz_controls_inner_right.addWidget(self.expand_button)

        # Compose layouts
        self.fuzz_controls_outer_layout.addLayout(self.fuzz_controls_inner_left)
        self.fuzz_controls_outer_layout.addLayout(self.fuzz_controls_inner_right)
        self._layout.addLayout(self.fuzz_controls_outer_layout)

        # Crashes table
        session = db.getSession()
        self.crashesModel = sqlalchemy_model.SqlalchemyModel(
            session,
            db.Crash,
            [
                ('Time', db.Crash.timestamp, 'timestamp', {}),
                ('RunID', db.Crash.runid, 'runid', {}),
                ('Reason', db.Crash.crashReason, 'crashReason', {}),
                ('Exploitability', db.Crash.exploitability, 'exploitability', {}),
                ('Ranks', db.Crash.ranksString, 'ranksString', {}),
                ('Crashash', db.Crash.crashash, 'crashash', {}),
                ('Crash Address', db.Crash.crashAddressString, 'crashAddressString', {}),
                ('RIP', db.Crash.instructionPointerString, 'instructionPointerString', {}),
                ('RSP', db.Crash.stackPointerString, 'stackPointerString', {}),
                ('RDI', db.Crash.rdi, 'rdi', {}),
                ('RSI', db.Crash.rsi, 'rsi', {}),
                ('RBP', db.Crash.rdx, 'rbp', {}),
                ('RAX', db.Crash.rax, 'rax', {}),
                ('RBX', db.Crash.rbx, 'rbx', {}),
                ('RCX', db.Crash.rcx, 'rcx', {}),
                ('RDX', db.Crash.rdx, 'rdx', {}),
            ],
            orderBy=desc(db.Crash.timestamp),
            filters={"target_config_slug": get_target_slug(config.config)})
        self.crashesTable = QTableView()
        self.crashesTable.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.crashesTable.setModel(self.crashesModel)
        self._layout.addWidget(self.crashesTable)
        self.crashesTable.horizontalHeader().setStretchLastSection(True)
        self.crashesTable.resizeColumnsToContents()
        self.crashesTable.show()
        self.crashesTable.clicked.connect(self.crashClicked)

        # Crash Browser, details about a crash
        self.crashBrowser = QTextBrowser()
        self.crashBrowser.setText("<NO CRASH SELECTED>")
        self.crashBrowser.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self._layout.addWidget(self.crashBrowser)

        self.statsWidget = stats.StatsWidget()
        self._layout.addWidget(self.statsWidget)

        # Set up stop button (and hide it)
        self.stop_button = QtWidgets.QPushButton("Stop Fuzzing")
        self.stop_button.hide()
        self._layout.addWidget(self.stop_button)

        self.triageExport = QtWidgets.QPushButton("Export Triage")
        self._layout.addWidget(self.triageExport)

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

        # Start the wizard when we click the button and update the tree when we're done
        self.wizard_button.clicked.connect(self.wizard_thread.start)
        self.wizard_thread.started.connect(partial(self.setCursor, Qt.WaitCursor))
        self.wizard_thread.finished.connect(self.unsetCursor)
        self.wizard_thread.resultReady.connect(self.wizard_finished)

        # Connect the context menu buttons
        self.expand_action.triggered.connect(self._func_tree.expandAll)
        self.collapse_action.triggered.connect(self._func_tree.collapseAll)
        self.check_action.triggered.connect(self.check_all)
        self.uncheck_action.triggered.connect(self.uncheck_all)

        # Filter the list of functions displayed when we type things into the boxes
        self.func_filter_box.textChanged.connect(self.func_proxy_model.setFilterFixedString)
        self.file_filter_box.textChanged.connect(self.file_proxy_model.setFilterFixedString)
        self.module_filter_box.textChanged.connect(self.module_proxy_model.setFilterFixedString)

        # Handle checks/unchecks in the target tree
        self._func_tree.itemCheckedStateChanged.connect(self.tree_changed)

        self.triageExport.clicked.connect(self.triageExportGui)

        # Fuzzer controll buttons for showing the panel and starting a run
        self.expand_button.clicked.connect(self.toggle_expansion)
        self.fuzzer_button.clicked.connect(self.server_thread.start)
        self.server_thread.finished.connect(self.start_all_threads)

        # Connect the stop button to the thread so we can pause it
        self.stop_button.clicked.connect(self.pause_all_threads)

        # Connect the thread counter to the thread pool
        self.thread_count.valueChanged.connect(self.change_thread_count)
        self.change_thread_count(self.thread_count.value())
        self.customContextMenuRequested.connect(self.contextMenuEvent)

    def change_thread_count(self, new_count):
        """ Creates new threads if we don't have as many as the user wants """
        if len(self.thread_holder) < new_count:
            self.thread_holder.append(FuzzerThread(config.config, self.target_data.filename))
            self.connect_thread_callbacks(self.thread_holder[-1])

    def start_all_threads(self):
        """ Maps over the thread list and starts all the threads """
        self.start_time = self.start_time if self.start_time is not None else time.time()
        self.thread_count.setDisabled(True)
        self.fuzzer_button.setDisabled(True)
        self.busy_label.show()

        for thread in self.thread_holder[:int(self.thread_count.value())]:
            thread.start()
        self.stop_button.show()

    def all_threads_paused(self):
        """ Updates the UI after we've sent the pause signal to all the threads"""
        self.fuzzer_button.setDisabled(False)
        self.thread_count.setDisabled(False)
        self.stop_button.hide()
        self.busy_label.hide()

    def pause_all_threads(self):
        """ Maps over the thread list and send the pause signal to all the threads"""
        for thread in self.thread_holder:
            thread.pause()
        self.all_threads_paused()

    def connect_thread_callbacks(self, fuzzer_thread):
        """ Sets up callbacks that should fire when any thread emits a signal (or should be received by all threads """
        # Update the run/crash/throughput variables after every fuzzing run
        fuzzer_thread.runComplete.connect(self.calculate_throughput)
        fuzzer_thread.runComplete.connect(self.check_for_completion)
        fuzzer_thread.foundCrash.connect(self.handle_new_crash)
        fuzzer_thread.server_crashed.connect(self.handle_server_crash)

        self.continuous_mode_cbox.stateChanged.connect(fuzzer_thread.continuous_state_changed)
        self.pause_mode_cbox.stateChanged.connect(fuzzer_thread.pause_state_changed)
        self.fuzz_timeout_box.valueChanged.connect(fuzzer_thread.fuzz_timeout_changed)
        self.tracer_timeout_box.valueChanged.connect(fuzzer_thread.tracer_timeout_changed)

    def check_for_completion(self):
        """ Filters the threads and checks if any are still running """
        still_running = list(filter(lambda k: k.should_fuzz, self.thread_holder))
        if len(still_running) == 0:
            self.all_threads_paused()

    def calculate_throughput(self):
        """ Calculate our current runs/second. """
        self.runs.increment()
        self.throughput.update(self.runs.value / float(time.time() - self.start_time))

    def handle_new_crash(self, thread, run_id):
        """ Updates the crash counter and pauses other threads if specified """
        self.crashesModel.update()
        self.crashesTable.resizeColumnsToContents()
        self.statsWidget.update()
        self.crash_counter.increment()
        crash = db.Crash.factory(run_id, get_target_slug(config.config))
        if not crash:
            return None
        self.crashes.append(crash)
        if not thread.should_fuzz:
            self.pause_all_threads()
        # self.triage_output.append(str(crash))
        self.crashes.append(crash)

    def handle_server_crash(self):
        """ Pauses fuzzing threads and attempts to restart the server if it crashes """
        self.pause_all_threads()
        self.server_thread.start()

    def build_func_tree(self):
        """ Build the function target display tree """
        self._func_tree.setSortingEnabled(False)
        self.model.clear()
        self.model.setHorizontalHeaderLabels(["Function Name",
                                              "File",
                                              "File Offset",
                                              "Order Seen",
                                              "Calling Module",
                                              # "Return Address",
                                              "Targeting Mode"])

        self.model.horizontalHeaderItem(0).setToolTip("The name of a fuzzable function")
        self.model.horizontalHeaderItem(1).setToolTip("The name of the file (if any) the function tried to read")
        self.model.horizontalHeaderItem(2).setToolTip(
            "The bytes in the file that the program tried to read (if available)")
        self.model.horizontalHeaderItem(3).setToolTip("The order in which the wizard encountered this function")
        self.model.horizontalHeaderItem(4).setToolTip(
            "Which part of the program called this function. .exe modules are generally the most promising")
        self.model.horizontalHeaderItem(5).setToolTip("How we re-identify whether we're calling this function again")

        for index, option in enumerate(self.target_data):
            funcname_widget = CheckboxTreeWidgetItem(self._func_tree, index, "{func_name}".format(**option))
            filename_widget = QStandardItem(option.get('source', None))
            filename_widget.setEditable(False)
            offset_widget = QStandardItem("0x{:x} - 0x{:x}".format(option['start'], option['end'])
                                          if ('end' in option and 'start' in option)
                                          else None)
            offset_widget.setEditable(False)
            funcname_widget.setCheckState(Qt.Checked if option["selected"] else Qt.Unchecked)
            funcname_widget.setColumnCount(3)

            add = []
            hx = []
            asc = []
            for address in range(0, min(len(option["buffer"]), 16 * 5), 16):
                add.append("0x%04X" % address)
                hx.append(" ".join("{:02X}".format(c) for c in option["buffer"][address:address + 16]))
                asc.append(
                    "".join((chr(c) if c in range(31, 127) else '.') for c in option["buffer"][address:address + 16]))
            addr = QStandardItem('\n'.join(add))
            hexstr = QStandardItem('\n'.join(hx))
            asciistr = QStandardItem('\n'.join(asc))
            addr.setEditable(False)
            hexstr.setEditable(False)
            asciistr.setEditable(False)
            addr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            hexstr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            asciistr.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            funcname_widget.appendRow([addr, hexstr, asciistr])

            idx_widget = QStandardItem(str(index))
            idx_widget.setEditable(False)
            mod_widget = QStandardItem(str(option.get('called_from', None)))
            mod_widget.setEditable(False)

            addr_widget = QStandardItem(str(option.get('retAddrOffset', None)))
            addr_widget.setEditable(False)

            mode_widget = QStandardItem(mode_labels[option.get('mode')])
            mode_widget.setData(option.get('mode'), role=Qt.UserRole)
            mode_widget.setData(index, role=Qt.UserRole + 1)
            mode_widget.setData(QBrush(QColor(0, 0, 0, 16)), role=Qt.BackgroundRole)

            self.model.appendRow([funcname_widget,
                                  filename_widget,
                                  offset_widget,
                                  idx_widget,
                                  mod_widget,
                                  # addr_widget,
                                  mode_widget])
            # self._func_tree.edit(self.model.indexFromItem(mode_widget))

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

    def get_visible_indices(self):
        """ Get the indices in the root model of all the visible items in the tree view """
        for row in range(self.module_proxy_model.rowCount()):
            yield self.func_proxy_model.mapToSource(
                self.file_proxy_model.mapToSource(
                    self.module_proxy_model.mapToSource(
                        self.module_proxy_model.index(row, 0))))

    def check_all(self):
        """ Check all the visible boxes in the tree view """
        self.target_data.pause()
        for index in self.get_visible_indices():
            self.model.itemFromIndex(index).setCheckState(Qt.Checked)
        self.target_data.unpause()

    def uncheck_all(self):
        """ The opposite of check_all """
        self.target_data.pause()
        for index in self.get_visible_indices():
            self.model.itemFromIndex(index).setCheckState(Qt.Unchecked)
        self.target_data.unpause()

    def contextMenuEvent(self, QContextMenuEvent):
        """ Displays the right-click menu """
        menu = QMenu(self)
        menu.addAction(self.expand_action)
        menu.addAction(self.collapse_action)
        menu.addAction(self.check_action)
        menu.addAction(self.uncheck_action)
        menu.popup(QContextMenuEvent.globalPos())

    def checksec_finished(self, checksec_output):
        target_path = config.config['target_application_path']
        target_string = "Target: {}\t Protections: {}".format(target_path, checksec_output)
        self.targetLabel.setText(target_string)

    def wizard_finished(self, wizard_output):
        """ Dump the results of a wizard run to the target file and rebuild the tree """
        self.target_data.set_target_list(wizard_output)
        self.build_func_tree()

    def save_crashes(self):
        """ Saves a csv of crash data """
        self.crashesModel.update()
        savefile, not_canceled = QFileDialog.getSaveFileName(self, filter="*.csv")
        if not_canceled:
            export_crash_data_to_csv(self.crashes, savefile)

    def toggle_expansion(self):
        """ Toggles whether or not the extended fuzzing controls are shown """
        if not self.extension_widget.isVisible():
            self.extension_widget.show()
            self.expand_button.setArrowType(Qt.UpArrow)
            self.adjustSize()
        else:
            self.extension_widget.hide()
            self.expand_button.setArrowType(Qt.DownArrow)
            self.adjustSize()

    def verboseCheckBox_clicked(self):
        state = self.verboseCheckBox.isChecked()
        config.config['verbose'] = 2 if state else False

    def triageExportGui(self):
        path = QFileDialog.getExistingDirectory(dir=".")
        if len(path) == 0:
            return
        triageExporter = triage.TriageExport(path)
        triageExporter.export()
        os.startfile(path)

    ## Clicked on Crash
    # When a cell is clicked in the crashes table, find the row
    # and update the Crash browser to show triage.txt
    def crashClicked(self, a):
        # row, col = a.row(), a.column()
        data = a.data(Qt.UserRole)
        crash = db.Crash.factory(data.runid)
        self.crashBrowser.setText(crash.output)


def main():
    app = QtWidgets.QApplication(sys.argv)

    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
