from PySide2.QtCore import QThread, Signal, Qt
from .instrument import wizard_run, fuzzer_run, tracer_run, start_server, triagerRun
import copy

class WizardThread(QThread):
    resultReady = Signal(list)

    def __init__(self, config_dict):
        QThread.__init__(self)
        self.config_dict = config_dict

    def run(self):
        self.resultReady.emit(wizard_run(self.config_dict))


class ServerThread(QThread):

    def run(self):
        start_server()


class FuzzerThread(QThread):
    foundCrash = Signal(QThread, object)
    runComplete = Signal()
    paused = Signal()
    server_crashed = Signal()

    def __init__(self, config_dict, target_file):
        QThread.__init__(self)
        self.target_file = target_file
        self.config_dict = config_dict
        self.should_fuzz = True

        self.config_dict['client_args'].append('-t')
        self.config_dict['client_args'].append(self.target_file)

    def __del__(self):
        self.should_fuzz = False

    def pause(self):
        self.should_fuzz = False
        self.paused.emit()

    def run(self):
        self.should_fuzz = True

        while self.should_fuzz:
            crashed, run_id = fuzzer_run(self.config_dict)

            if crashed:
                if self.config_dict['exit_early']:
                    self.pause()
                #formatted, raw = tracer_run(self.config_dict, run_id)
                triagerInfo = triagerRun(self.config_dict, run_id)
                triagerInfo = copy.deepcopy(triagerInfo)
                self.foundCrash.emit(self, triagerInfo)

            if not self.config_dict['continuous']:
                self.pause()

            if run_id == -1:
                self.server_crashed.emit()
                self.pause()
            self.runComplete.emit()

    def continuous_state_changed(self, new_state):
        self.config_dict['continuous'] = (new_state == Qt.Checked)

    def pause_state_changed(self, new_state):
        self.config_dict['exit_early'] = (new_state == Qt.Checked)

    def fuzz_timeout_changed(self, new_timeout):
        self.config_dict['fuzz_timeout'] = None if int(new_timeout) == 0 else int(new_timeout)

    def tracer_timeout_changed(self, new_timeout):
        self.config_dict['tracer_timeout'] = None if int(new_timeout) == 0 else int(new_timeout)
