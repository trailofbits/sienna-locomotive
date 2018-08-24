from PySide2 import QtWidgets
import db
import statistics
from db import Crash

class StatsWidget(QtWidgets.QWidget):
    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        self.layout = QtWidgets.QVBoxLayout()
        self.web = QtWidgets.QTextBrowser()
        self.web.setOpenExternalLinks(True)
        self.web.setOpenLinks(True)
        self.layout.addWidget(self.web)
        self.setLayout(self.layout)

        self.update()




    def toHTML(self):
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
        <tr> <td class="haupt">Crashes</td>  <td>%d</td></tr>
        <tr> <td class="haupt">Unique Crashes</td> <td>%d</td></tr>
        <tr> <td class="haupt">Duplicate Crashes</td> <td>%d</td></tr>
        <!--<tr colspan="4"><td><hr/></td></tr>-->
        <!--<tr colspan="4" ><td colspan="4" class="heading">Exploitability</td></tr>-->
        <tr> <td class="haupt">Ranks (Mean, Median): </td> <td>%0.1f, %0.1f</td></tr>
        <tr> <td class="haupt">High Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Medium Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Low Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">Unknown Exploitability</td> <td>%d</td></tr>
        <tr> <td class="haupt">None Exploitability</td> <td>%d</td></tr>
    </table>
</html>
        """ % (
            self.crashesCnt,
            self.uniquesCnt,
            self.dupesCount,
            self.ranksMean,
            self.ranksMedian,
            self.exploitabilityCnts['High'],
            self.exploitabilityCnts['Medium'],
            self.exploitabilityCnts['Low'],
            self.exploitabilityCnts['Unknown'],
            self.exploitabilityCnts['None']
        )

    def update(self):
        session = db.getSession()

        self.crashes = Crash.getAll()
        self.crashesCnt = len(self.crashes)

        self.uniquesCnt = session.query(Crash).distinct(Crash.rank).group_by(Crash.rank).count()
        self.dupesCount = self.crashesCnt - self.uniquesCnt
        self.ranks = [ _.rank for _ in self.crashes ]
        self.ranksMean      = statistics.mean(self.ranks)
        self.ranksMedian    = statistics.median(self.ranks)

        self.exploitabilityCnts = {}

        self.exploitabilityCnts['High'] = session.query(Crash).filter(Crash.rank==4).count()
        self.exploitabilityCnts['Medium'] = session.query(Crash).filter(Crash.rank==3).count()
        self.exploitabilityCnts['Low'] = session.query(Crash).filter(Crash.rank==2).count()
        self.exploitabilityCnts['Unknown'] = session.query(Crash).filter(Crash.rank==1).count()
        self.exploitabilityCnts['None'] = session.query(Crash).filter(Crash.rank==0).count()

        html = self.toHTML()
        self.web.setText(html)