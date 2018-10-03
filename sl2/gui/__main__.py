######################################################
## @package gui
# Code for the QT gui

import sys
import time
from functools import partial
from multiprocessing import cpu_count

from PySide2 import QtWidgets
from PySide2.QtCore import Qt, QSize
from PySide2.QtGui import QFontDatabase, QMovie, QStandardItem, QBrush, QColor
from sqlalchemy import desc

from sl2 import db
from sl2.harness import config
from sl2.harness.state import sanity_checks, get_target, export_crash_data_to_csv, get_target_slug, TriageExport
from sl2.harness.threads import ChecksecThread, WizardThread, FuzzerThread, ServerThread
from sl2.reporting.__main__ import generate_report

from . import stats
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

## class MainWindow
# Main window for gui
class MainWindow(QtWidgets.QMainWindow):

    ## Creates Widgets, Connects Signals, Draws Window
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.crashes = []
        self.thread_holder = []
        self.paused_fuzzer_threads = []
        self.start_time = None

        # Select config profile before starting
        self.cfg = ConfigWindow()
        if self.cfg.exec() == QtWidgets.QDialog.Rejected:
            sys.exit(1)

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
        self.server_thread = ServerThread(close_on_exit=True)

        # CREATE WIDGETS #

        # Menu bar
        self.menu_bar = self.menuBar()
        self.file_menu = self.menu_bar.addMenu("&File")
        self.change_profile_action = self.file_menu.addAction("Change Profile")
        self.open_report_in_browser = QtWidgets.QAction("Open exported report in browser",
                                                        self, checkable=True)
        self.file_menu.addAction(self.open_report_in_browser)
        self.open_report_in_browser.setChecked(True)

        # Target info
        self.target_status = QtWidgets.QStatusBar()
        self.target_label = QtWidgets.QLabel()
        self.target_status.addWidget(self.target_label)
        self._layout.addWidget(self.target_status)
        self.checksec_thread.start()
        self.checksec_thread.result_ready.connect(self.checksec_finished)

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
        self.expand_action = QtWidgets.QAction("Expand All")
        self.collapse_action = QtWidgets.QAction("Collapse All")
        self.check_action = QtWidgets.QAction("Check All")
        self.uncheck_action = QtWidgets.QAction("Uncheck All")

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
        if not self.target_data.target_list:
            self.fuzzer_button.setEnabled(False)

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
        self.verbose_cbox = QtWidgets.QCheckBox()
        self.verbose_cbox.clicked.connect(self.toggle_verbose_state)

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
        self.extension_layout.addWidget(self.verbose_cbox, 1, 4, 1, 1, Qt.AlignLeft)

        self.fuzz_controls_inner_right.addWidget(self.expand_button)

        # Compose layouts
        self.fuzz_controls_outer_layout.addLayout(self.fuzz_controls_inner_left)
        self.fuzz_controls_outer_layout.addLayout(self.fuzz_controls_inner_right)
        self._layout.addLayout(self.fuzz_controls_outer_layout)

        # Crashes table
        session = db.getSession()
        self.crashes_model = sqlalchemy_model.SqlalchemyModel(
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
        self.crashes_table = QtWidgets.QTableView()
        self.crashes_table.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.crashes_table.setModel(self.crashes_model)
        self._layout.addWidget(self.crashes_table)
        self.crashes_table.horizontalHeader().setStretchLastSection(True)
        self.crashes_table.resizeColumnsToContents()
        self.crashes_table.show()
        self.crashes_table.clicked.connect(self.crashClicked)

        # Crash Browser, details about a crash
        self.crash_browser = QtWidgets.QTextBrowser()
        self.crash_browser.setText("<NO CRASH SELECTED>")
        self.crash_browser.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self._layout.addWidget(self.crash_browser)

        self.stats_widget = stats.StatsWidget(get_target_slug(config.config))
        self._layout.addWidget(self.stats_widget)

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
        self.change_profile_action.triggered.connect(self.change_profile)

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
        self.wizard_thread.result_ready.connect(self.wizard_finished)

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

        # Fuzzer control buttons for showing the panel and starting a run
        self.expand_button.clicked.connect(self.toggle_expansion)
        self.fuzzer_button.clicked.connect(self.server_thread.start)
        self.server_thread.finished.connect(self.start_all_threads)

        # If the user changes the continuous or pause mode, then we make sure the
        # two are consistent.
        self.pause_mode_cbox.stateChanged.connect(self.unify_pause_state)
        self.continuous_mode_cbox.stateChanged.connect(self.unify_continuous_state)

        # Connect the stop button to the thread so we can pause it
        self.stop_button.clicked.connect(self.pause_all_threads)

        # Connect the thread counter to the thread pool
        self.thread_count.valueChanged.connect(self.change_thread_count)
        self.change_thread_count(self.thread_count.value())
        self.customContextMenuRequested.connect(self.contextMenuEvent)

    def change_profile(self):
        self.close()
        main_window = MainWindow()
        main_window.show()

    ## Signal handler that updates the thread count based on the gui
    def change_thread_count(self, new_count):
        """ Creates new threads if we don't have as many as the user wants """
        if len(self.thread_holder) < new_count:
            self.thread_holder.append(FuzzerThread(config.config, self.target_data.filename))
            self.connect_thread_callbacks(self.thread_holder[-1])

    ## Signal handler that starts all the selected threads
    def start_all_threads(self):
        """ Maps over the thread list and starts all the threads """
        self.start_time = self.start_time if self.start_time is not None else time.time()

        # Don't allow the user to change profiles while running fuzzer threads.
        self.change_profile_action.setDisabled(True)

        self.thread_count.setDisabled(True)
        self.fuzzer_button.setDisabled(True)
        self.busy_label.show()

        focus_threads = self.thread_holder[:int(self.thread_count.value())]

        for thread in focus_threads:
            if (not thread.isRunning() and thread.should_fuzz) or thread in self.paused_fuzzer_threads:
                thread.start()

        self.paused_fuzzer_threads.clear()
        self.stop_button.show()

    ## Callback that fires when all threads are paused. Changes the UI state to allow clicking buttons
    def all_threads_paused(self):
        """ Updates the UI after we've sent the pause signal to all the threads"""
        self.change_profile_action.setDisabled(False)
        self.fuzzer_button.setDisabled(False)
        self.thread_count.setDisabled(False)
        self.stop_button.hide()
        self.busy_label.hide()

    ## Signal handler that pauses all the threads
    def pause_all_threads(self):
        """ Maps over the thread list and send the pause signal to all the threads"""
        for thread in self.thread_holder:
            thread.pause()
        self.all_threads_paused()

    ## Helper method to connect all the necessary callbacks to a given fuzzer thread
    #  @param fuzzer_thread - thread to connect callbacks to
    def connect_thread_callbacks(self, fuzzer_thread):
        """ Sets up callbacks that should fire when any thread emits a signal (or should be received by all threads """
        # Update the run/crash/throughput variables after every fuzzing run
        fuzzer_thread.run_complete.connect(self.calculate_throughput)
        fuzzer_thread.run_complete.connect(self.check_for_completion)
        fuzzer_thread.paused.connect(self.handle_paused_fuzzer_thread)
        fuzzer_thread.found_crash.connect(self.handle_new_crash)
        fuzzer_thread.server_crashed.connect(self.handle_server_crash)
        fuzzer_thread.tracer_failed.connect(self.handle_tracer_failure)

        self.continuous_mode_cbox.stateChanged.connect(fuzzer_thread.continuous_state_changed)
        self.pause_mode_cbox.stateChanged.connect(fuzzer_thread.pause_state_changed)
        self.fuzz_timeout_box.valueChanged.connect(fuzzer_thread.fuzz_timeout_changed)
        self.tracer_timeout_box.valueChanged.connect(fuzzer_thread.tracer_timeout_changed)

    ## Signal handler that checks to see if anny threads are running
    def check_for_completion(self):
        """ Filters the threads and checks if any are still running """
        still_running = list(filter(lambda k: k.should_fuzz, self.thread_holder))
        if len(still_running) == 0:
            self.all_threads_paused()

    ## Signal handler that calculates runs/second
    def calculate_throughput(self):
        """ Calculate our current runs/second. """
        self.runs.increment()
        self.throughput.update(self.runs.value / float(time.time() - self.start_time))

    ## Signal handler that helps avoid race conditions when restarting threads
    def handle_paused_fuzzer_thread(self, fuzzer_thread):
        if fuzzer_thread not in self.paused_fuzzer_threads:
            self.paused_fuzzer_threads.append(fuzzer_thread)

    ## Signal handler that automatically retrieves data for a new crash whenver one is found
    def handle_new_crash(self, thread, run_id):
        """ Updates the crash counter and pauses other threads if specified """
        self.crashes_model.update()
        self.crashes_table.resizeColumnsToContents()
        self.stats_widget.update()
        self.crash_counter.increment()
        crash = db.Crash.factory(run_id, get_target_slug(config.config))
        if not crash:
            return None
        self.crashes.append(crash)
        if not thread.should_fuzz:
            self.pause_all_threads()
        # self.triage_output.append(str(crash))
        self.crashes.append(crash)

    ## Signal handler that pauses fuzzing threads and restarts the server in the event that it crashes or hangs up
    def handle_server_crash(self):
        """ Pauses fuzzing threads and attempts to restart the server if it crashes """
        self.pause_all_threads()
        self.server_thread.start()

    ## Signal handler that displays a warning if for some reason the tracer fails.
    def handle_tracer_failure(self):
        """ Alert the user if a tracer run fails. """
        # TODO(ww): Does it make sense to pause the fuzzing threads here?
        QtWidgets.QMessageBox.critical(
            None, "Tracer failure",
            "Found a crash but couldn't trace it.\nTry running the tracer manually via sl2-cli?")

    ## Builds the tree of targetable functions to display
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

    ## Signal handler that updates the target file on the disk whenever a checkbox in the tree is clicked
    def tree_changed(self, widget, is_checked):
        """ Handle when an item in the function tree is checked """
        self.target_data.update(widget.index, selected=is_checked)

    ## Maps indices of items shown in the filtered tree currently displayed to indices in the underlying model
    def get_visible_indices(self):
        """ Get the indices in the root model of all the visible items in the tree view """
        for row in range(self.module_proxy_model.rowCount()):
            yield self.func_proxy_model.mapToSource(
                self.file_proxy_model.mapToSource(
                    self.module_proxy_model.mapToSource(
                        self.module_proxy_model.index(row, 0))))

    ## Checks/Unchecks all members of the function targeting tree
    def check_all(self):
        """ Check all the visible boxes in the tree view """
        self.target_data.pause()
        for index in self.get_visible_indices():
            self.model.itemFromIndex(index).setCheckState(Qt.Checked)
        self.target_data.unpause()

    ## Checks/Unchecks all members of the function targeting tree
    def uncheck_all(self):
        """ The opposite of check_all """
        self.target_data.pause()
        for index in self.get_visible_indices():
            self.model.itemFromIndex(index).setCheckState(Qt.Unchecked)
        self.target_data.unpause()

    ## Handler for displaying a custom context menu
    def contextMenuEvent(self, QContextMenuEvent):
        """ Displays the right-click menu """
        menu = QtWidgets.QMenu(self)
        menu.addAction(self.expand_action)
        menu.addAction(self.collapse_action)
        menu.addAction(self.check_action)
        menu.addAction(self.uncheck_action)
        menu.popup(QContextMenuEvent.globalPos())

    ## Signal handler that handles checksec results after the executable finishes.
    def checksec_finished(self, checksec_output):
        target_path = config.config['target_application_path']
        target_string = "Target: {}\t Protections: {}".format(target_path, checksec_output)
        self.target_label.setText(target_string)

    ## Signal handler that handles wizard results after the executable finishes.
    def wizard_finished(self, wizard_output):
        """ Dump the results of a wizard run to the target file and rebuild the tree """
        if wizard_output:
            self.target_data.set_target_list(wizard_output)
            self.build_func_tree()
            self.fuzzer_button.setEnabled(True)
        else:
            QtWidgets.QMessageBox.critical(None, "Wizard failure",
                                           "No wizard results; is the target 64-bit?")

    ## (DEPRECATED) saves a csv file of the crash results. No longer used.
    def save_crashes(self):
        """ Saves a csv of crash data """
        self.crashes_model.update()
        savefile, not_canceled = QtWidgets.QFileDialog.getSaveFileName(self, filter="*.csv")
        if not_canceled:
            export_crash_data_to_csv(self.crashes, savefile)

    ## Expands/Un-Expands all the items in the function targeting tree
    def toggle_expansion(self):
        """ Toggles whether or not the extended fuzzing controls are shown """
        if not self.extension_widget.isVisible():
            self.extension_widget.show()
            self.expand_button.setArrowType(Qt.UpArrow)
        else:
            self.extension_widget.hide()
            self.expand_button.setArrowType(Qt.DownArrow)

        if not self.sizeHint().isValid():
            self.adjustSize()

    ## Prevent the race condition when stopping/restarting fuzzer threads
    def unify_pause_state(self, state):
        """
            Keeps the state of the "continuous" and "pause" checkboxes consistent.

            Any attempt to enable "pause" enables "continuous".
        """
        if state == Qt.Checked:
            self.continuous_mode_cbox.setChecked(True)

    ## Prevent the race condition when stopping/restarting fuzzer threads
    def unify_continuous_state(self, state):
        """
            Keeps the state of the "continuous" and "pause" checkboxes consistent.

            Any attempt to disable "continuous" disables "pause".
        """
        if state == Qt.Unchecked:
            self.pause_mode_cbox.setChecked(False)

    ## Signal handler that updates the verbosity state when the checkbox in the gui is clicked
    def toggle_verbose_state(self):
        state = self.verbose_cbox.isChecked()
        config.config['verbose'] = 2 if state else False

    ## Button callback that allows the user to select a location to save a csv file and a fuzzing report
    def triageExportGui(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(dir=".")
        if len(path) == 0:
            return

        exporter = TriageExport(path, get_target_slug(config.config))
        num_crashes = len(exporter.get_crashes())

        print("Exporting {} crashes".format(num_crashes))

        exporter_progress = QtWidgets.QProgressDialog(
            "Exporting crashes...", None, 0, num_crashes - 1, self)
        exporter_progress.setAutoClose(True)
        exporter_progress.setWindowModality(Qt.WindowModal)
        # Only show the progressbar if the operation is expected to take more than 1.5 seconds.
        exporter_progress.setMinimumDuration(1500)

        exporter.export(export_cb=exporter_progress.setValue)

        generate_report(dest=path, browser=self.open_report_in_browser.isChecked())

    ## Clicked on Crash
    # When a cell is clicked in the crashes table, find the row
    # and update the Crash browser to show triage.txt
    def crashClicked(self, a):
        # row, col = a.row(), a.column()
        data = a.data(Qt.UserRole)
        crash = db.Crash.factory(data.runid)
        self.crash_browser.setText(crash.output)

## Build a GUI window and display it to the user.
def main():
    app = QtWidgets.QApplication(sys.argv)
    sane, errors = sanity_checks(exit=False)

    if not sane:
        QtWidgets.QMessageBox.critical(None, "Sanity check failure",
                                       "\n".join(errors))
        sys.exit(1)

    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
