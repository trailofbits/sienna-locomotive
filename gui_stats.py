#
import sys
import postprocess
from PySide2 import QtWidgets
from PySide2.QtCore import Qt, QSize, QModelIndex
from PySide2.QtCore import QThread, Signal, Qt
from functools import partial

from PySide2.QtWidgets import QTableView, QVBoxLayout, QApplication
from PySide2.QtCore import QAbstractTableModel


class PostprocThread(QThread):
    resultReady = Signal(list)

    def __init__(self, cfg, callback):
        QThread.__init__(self)
        self.cfg = cfg
        self.callback = callback

    def run(self):
        rollup = postprocess.Rollup()
        rollup.process(self.callback)
        self.resultReady.emit(rollup)

class RollupModel(QAbstractTableModel):


    def attachModel(self, rollup):
        self.rollup = rollup


    def horizontalHeaderItem(self, col):
        ret = self.rollup.cols()[col]
        print("ret", ret)
        return ret

    def rowCount(self, parent):
        return self.rollup.rowsCount()

    def columnCount( self, parent ):
        return len(self.rollup.cols())

    def data(self, index, role):
        return self.rollup.toCSV()[index.row()][index.column()]


class MainWin(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)


        self.setWindowTitle("Stats (SL2)")
        self.setMinimumSize(QSize(1024, 768))

        self.centralWidget = QtWidgets.QWidget(self)
        self.setCentralWidget(self.centralWidget)
        self.layout = QtWidgets.QVBoxLayout(self.centralWidget)
        self.centralWidget.setLayout(self.layout)

        # browser
        self.web = QtWidgets.QTextBrowser()
        self.web.setOpenExternalLinks(True)
        self.web.setOpenLinks(True)
        html = """<html>
    <table>
        <tr><td>1</td><td>2</td></tr>
        <tr><td>3</td><td>4</td></tr>
    </table>
    <a href="http://www.google.com">Google</a>
</html>"""
        self.web.setHtml(html)
        self.layout.addWidget(self.web)

        # table
        self.tableModel = RollupModel()
        self.table = QTableView()
        self.table.show()
        self.layout.addWidget(self.table)


        #Postproc thread
        self.postprocThread = PostprocThread({}, self.postprocCallback)

        # Postproc button
        self.postprocButton = QtWidgets.QPushButton("Run Post Processing")
        self.layout.addWidget(self.postprocButton)
        self.postprocButton.clicked.connect(self.postprocThread.start)
        self.postprocThread.started.connect(partial(self.setCursor, Qt.WaitCursor))
        self.postprocThread.finished.connect(self.unsetCursor)
        self.postprocThread.resultReady.connect(self.postprocFinished)


        # Status Bar
        self.statusBar = QtWidgets.QStatusBar()
        self.statusText = QtWidgets.QLabel("Status!")
        self.statusBar.addWidget(self.statusText)
        self.layout.addWidget(self.statusBar)

    def postprocFinished(self, rollup):
        self.tableModel.attachModel(rollup)
        self.table.setModel(self.tableModel)
        print("rollup", rollup)


    def postprocCallback( self, rmsg ):
        dupe = "(Duplicate)" if rmsg.duplicate else ""
        percentdone = 100*rmsg.i / rmsg.iCnt
        msg =  "%d%% done %s %s" % (percentdone, rmsg.path, dupe)
        print(msg)
        self.status(msg)

    def status(self, msg):
        self.statusText.setText(msg)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    mainWin = MainWin()
    mainWin.show()
    sys.exit(app.exec_())