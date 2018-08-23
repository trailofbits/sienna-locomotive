from PySide2.QtSql import QSqlTableModel
from PySide2.QtCore import  Qt

class SqlalchemyModel(QSqlTableModel):

    def __init__(self, session, clazz, cols):
        super().__init__()

        self.session        = session
        self.clazz          = clazz
        self.cols           = cols
        self.rows           = None
        self.update()


    def headerData( self, section, orientation, role ):
        try:
            return self.cols[section][0]
        except:
            print("No header data for section", section, role)

        return "<ERROR>"


    def flags(self, i):
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


    def update(self):
        self.layoutAboutToBeChanged.emit()
        self.rows = self.session.query( self.clazz ).all()
        self.layoutChanged.emit()

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.cols)

    def data(self, index, role ):

        # If we return stuff on other roles we get weird
        # check boxes in the cells
        if role!=Qt.DisplayRole:
            return None


        row = self.rows[ index.row() ]
        name = self.cols[ index.column() ][2]

        ret = getattr(  row, name )
        return ret

        return None

    def setData( self, index, value, role ):
        pass