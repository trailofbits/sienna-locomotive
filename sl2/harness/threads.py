from PySide2.QtCore import QThread, Signal, Qt

from .state import get_target_slug
from .instrument import wizard_run, fuzzer_run, start_server, triager_run
from sl2 import db
from sl2.db.run_block import SessionManager


## class ChecksecThread
#  Runs Checksec once in a background thread so as not to stall the GUI
class ChecksecThread(QThread):
    result_ready = Signal(str)

    def __init__(self, target_path):
        QThread.__init__(self)
        self.target_path = target_path

    def run(self):
        checksec_output = db.Checksec.byExecutable(self.target_path).short_description()
        self.result_ready.emit(checksec_output)


## class WizardThread
#  Runs the Wizard once in a background thread so as not to stall the GUI
class WizardThread(QThread):
    result_ready = Signal(list)

    def __init__(self, config_dict):
        QThread.__init__(self)
        self.config_dict = config_dict

    def run(self):
        self.result_ready.emit(wizard_run(self.config_dict))


## class ServerThread
#  Runs the Server once in a background thread so as not to stall the GUI
class ServerThread(QThread):
    def __init__(self, close_on_exit=False):
        QThread.__init__(self)
        self.close_on_exit = close_on_exit

    def run(self):
        start_server(close_on_exit=self.close_on_exit)


## class FuzzerThread
#  Duplicates the functionality of instrument.fuzz_and_triage. Runs the fuzzer in a loop, automatically triaging once we
#  find a crash.
class FuzzerThread(QThread):
    found_crash = Signal(QThread, str)
    run_complete = Signal()
    paused = Signal(object)
    server_crashed = Signal()
    tracer_failed = Signal()

    def __init__(self, config_dict, target_file):
        QThread.__init__(self)
        self.target_file = target_file
        self.config_dict = config_dict
        self.should_fuzz = True

        self.config_dict["client_args"].append("-t")
        self.config_dict["client_args"].append(self.target_file)

    def __del__(self):
        self.should_fuzz = False

    ## Marks this object as paused and emits the paused signal
    def pause(self):
        self.should_fuzz = False
        self.paused.emit(self)

    ## Creates a session manager and records runs in a loop, triaging where necessary
    def run(self):
        self.should_fuzz = True

        with SessionManager(get_target_slug(self.config_dict)) as manager:
            while self.should_fuzz:
                crashed, run = fuzzer_run(self.config_dict, self.target_file)
                manager.run_complete(run, found_crash=crashed)

                if crashed:
                    if self.config_dict["exit_early"]:
                        self.pause()
                    # We can't pass this object to another thread since it's database, so just returning the runid
                    triagerInfo = triager_run(self.config_dict, run.run_id)

                    if triagerInfo:
                        self.found_crash.emit(self, str(run.run_id))
                    else:
                        self.tracer_failed.emit()

                if not self.config_dict["continuous"]:
                    self.pause()

                if run.run_id == -1:
                    self.server_crashed.emit()
                    self.pause()
                self.run_complete.emit()

    ## Writes changes in the continuous state to the config dict
    def continuous_state_changed(self, new_state):
        self.config_dict["continuous"] = new_state == Qt.Checked

    ## Writes changes in the pause state to the config dict
    def pause_state_changed(self, new_state):
        self.config_dict["exit_early"] = new_state == Qt.Checked

    ## Writes changes in the fuzz timeout to the config dict
    def fuzz_timeout_changed(self, new_timeout):
        self.config_dict["fuzz_timeout"] = None if int(new_timeout) == 0 else int(new_timeout)

    ## Writes changes in the tracer timeout to the config dict
    def tracer_timeout_changed(self, new_timeout):
        self.config_dict["tracer_timeout"] = None if int(new_timeout) == 0 else int(new_timeout)
