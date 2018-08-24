from PySide2.QtSql import QSqlTableModel
from PySide2.QtCore import  Qt

class SqlalchemyModel(QSqlTableModel):

    def __init__(self, session, clazz, cols, orderBy, sort=(0,0) ):
        super().__init__()

        self.session        = session
        self.clazz          = clazz
        self.cols           = cols
        self.rows           = None
        # sort is (column, order )
        self.sort           = sort
        self.orderBy        = orderBy
        self.update()


    def headerData( self, section, orientation, role ):
        try:
            ret = self.cols[section][0]
        except:
            return None

        if role!=Qt.DisplayRole or orientation!=Qt.Horizontal:
            return None

        return ret


    def flags(self, i):
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


    def update(self):
        self.layoutAboutToBeChanged.emit()

        self.rows = self.session.query( self.clazz ).\
            order_by(self.orderBy).\
            all()
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
        ret = str(ret)
        return ret




    def sort( self, col, order ):
        self.sort = (col, order)
        print("sort", sort)
        self.update()

    def setData( self, index, value, role ):
        pass