from PyQt5.QtCore import QThread, pyqtSignal
from .config import config
from .instrument import wizard_run

class WizardThread(QThread):
    resultReady = pyqtSignal(list)

    def __init__(self):
        QThread.__init__(self)

    def __del__(self):
        self.wait()

    def run(self):
        self.resultReady.emit(wizard_run(config))