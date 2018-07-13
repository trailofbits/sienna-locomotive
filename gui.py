import sys

from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt

from harness import config


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)

        self.setWindowTitle("Sienna Locomotive 2")

        self.get_config()

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)

        self._layout = QtWidgets.QGridLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        self._func_tree = QtWidgets.QTreeWidget()
        self._layout.addWidget(self._func_tree)

        for i in range(3):
            widget = QtWidgets.QTreeWidgetItem()
            widget.setCheckState(0, Qt.Unchecked)
            widget.setText(0, "Foobar")
            widget.addChild(QtWidgets.QTreeWidgetItem())
            self._func_tree.insertTopLevelItem(i, widget)

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
