from PyQt5.QtCore import QThread, pyqtSignal
import time
from .instrument import wizard_run, fuzzer_run, triage_run, start_server


class WizardThread(QThread):
    resultReady = pyqtSignal(list)

    def __init__(self, config_dict):
        QThread.__init__(self)
        self.config_dict = config_dict

    def __del__(self):
        self.wait()

    def run(self):
        self.resultReady.emit(wizard_run(self.config_dict))


class FuzzerThread(QThread):
    foundCrash = pyqtSignal(str)
    runComplete = pyqtSignal(float)
    paused = pyqtSignal()

    def __init__(self, config_dict, target_file):
        QThread.__init__(self)
        self.target_file = target_file
        self.config_dict = config_dict
        self.should_fuzz = True
        self.start_time = time.time()

    def __del__(self):
        self.should_fuzz = False
        self.wait()

    def pause(self):
        self.should_fuzz = False
        self.paused.emit()

    def run(self):
        self.should_fuzz = True

        start_server()

        self.config_dict['client_args'].append('-t')
        self.config_dict['client_args'].append(self.target_file)

        # self.start_time = time.time()

        while self.should_fuzz:
            crashed, run_id = fuzzer_run(self.config_dict)

            if crashed:
                formatted = triage_run(self.config_dict, run_id)
                self.foundCrash.emit(formatted)

                if self.config_dict['exit_early']:
                    self.should_fuzz = False

            self.runComplete.emit(float(time.time() - self.start_time))

            if not self.config_dict['continuous']:
                break
