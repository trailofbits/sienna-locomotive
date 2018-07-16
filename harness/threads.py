from PyQt5.QtCore import QThread, pyqtSignal
from .instrument import wizard_run, fuzzer_run, triage_run


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

    def __init__(self, config_dict, target_file):
        QThread.__init__(self)
        self.target_file = target_file
        self.config_dict = config_dict

    def __del__(self):
        self.wait()

    def run(self):
        self.config_dict['client_args'].append('-t')
        self.config_dict['client_args'].append(self.target_file)
        crashed, run_id = fuzzer_run(self.config_dict)
        if crashed:
            formatted = triage_run(self.config_dict, run_id)
            self.foundCrash.emit(formatted)

