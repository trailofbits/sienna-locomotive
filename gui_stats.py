#
import sys
import postprocess
from PySide2 import QtWidgets
from PySide2.QtCore import Qt, QSize, QModelIndex
from PySide2.QtCore import QThread, Signal, Qt
from functools import partial
import statistics

from PySide2.QtWidgets import QTableWidget, QVBoxLayout, QApplication, QTableWidgetItem
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
        return ret

    def rowCount(self, parent=None):
        return self.rollup.rowCount()

    def cols(self):
        return self.rollup.cols()

    def columnCount( self, parent=None ):
        return len(self.rollup.cols())

    # def data(self, index, role):
    #     return self.dataCell( index.row(), index.column() )

    def dataCell(self, row, col ):
        return self.rollup.toCSV()[row][col]

    def item( self, row, col ):
        data = self.dataCell( row, col )
        ret = QTableWidgetItem(str(data))
        return ret

    def toHTML(self):
        csv = self.rollup.toCSV()

        rankMedian = 0
        try:
            ranks = [ _[7] for _ in csv ]
            rankMedian = statistics.median(ranks)
        except:
            pass
        return """
<html>
    <head>
        <style>
            .haupt  {  font-weight: bold; }
            td      {  padding-left: 15px; }
            .heading  {  font-weight: bold; background-color: #dddddd }
        </style>
    </head>
    <table width="1024px">
        <tr> <td class="haupt">Unique Crashes</td>  <td>%d</td></tr>
        <tr> <td class="haupt">Duplicate Crashes</td> <td>%d</td></tr>
        <!--<tr colspan="4"><td><hr/></td></tr>-->
        <!--<tr colspan="4" ><td colspan="4" class="heading">Exploitability</td></tr>-->
        <tr> <td class="haupt">Median rank</td> <td>%0.1f</td></tr>
        <tr> <td class="haupt">High Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Medium Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Low Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Unknown Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">None Exploitability</td> <td>%d</td></tr>
    </table>
</html>
        """ % (
            self.rollup.rowCount(),
            self.rollup.dupes,
            rankMedian,
            self.rollup.rankStats["High"],
            self.rollup.rankStats["Medium"],
            self.rollup.rankStats["Low"],
            self.rollup.rankStats["Unknown"],
            self.rollup.rankStats["None"]
        )
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
        self.layout.addWidget(self.web)

        # table
        self.tableModel = RollupModel()
        self.table = QTableWidget()
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
        m = self.tableModel
        m.attachModel(rollup)
        colLabels = m.cols()
        colLabels = [ str(_) for _ in colLabels ]
        self.table.clear()
        self.table.setRowCount(m.rowCount())
        self.table.setColumnCount(m.columnCount())
        self.table.setHorizontalHeaderLabels( colLabels )
        csv = rollup.toCSV()
        for row in range(m.rowCount()):
            for col in range(m.columnCount()):
                item = m.item(row,col)
                self.table.setItem( row, col, item )

        # Lets skip col #6, since it's the minidump path and not that important
        for col in [0,1,2,3,4,5,7,8]:
            self.table.resizeColumnToContents(col)

        self.web.setHtml( m.toHTML() )


    def postprocCallback( self, rmsg ):
        dupe = "(Duplicate)" if rmsg.duplicate else ""
        percentdone = 100*rmsg.i / rmsg.iCnt
        msg =  "%d%% done %s %s" % (percentdone, rmsg.path, dupe)
        self.status(msg)

    def status(self, msg):
        self.statusText.setText(msg)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    mainWin = MainWin()
    mainWin.show()
    sys.exit(app.exec_())