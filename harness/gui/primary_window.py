import sys

from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)

        self.setWindowTitle("Sienna Locomotive 2")

        _central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(_central_widget)

        self._layout = QtWidgets.QGridLayout(_central_widget)
        _central_widget.setLayout(self._layout)

        self._func_tree = QtWidgets.QTreeWidget()
        self._layout.addWidget(self._func_tree)

        for i in range(3):
            widget = QtWidgets.QTreeWidgetItem()
            widget.setCheckState(0, Qt.Unchecked)
            widget.setText(0, "FOOBar")
            widget.addChild(QtWidgets.QTreeWidgetItem())
            self._func_tree.insertTopLevelItem(i, widget)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())
