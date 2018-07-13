import sys
import json

from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QSize

from harness import config
from harness.state import get_target


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)

        self.setWindowTitle("Sienna Locomotive 2")
        self.setMinimumSize(QSize(800, 600))

        self.get_config()

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)

        self._layout = QtWidgets.QGridLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        target_data = get_target(config.config)

        self._func_tree = QtWidgets.QTreeWidget()
        self._layout.addWidget(self._func_tree)

        for option in target_data:
            widget = QtWidgets.QTreeWidgetItem()
            widget.setCheckState(0, Qt.Checked if option["selected"] else Qt.Unchecked)
            widget.setText(0, option["func_name"])
            self._func_tree.insertTopLevelItem(0, widget)

    def get_config(self):
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
