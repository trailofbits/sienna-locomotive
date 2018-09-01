############################################################################
## @package sqlalchemy_model
#
from PySide2.QtSql import QSqlTableModel
from PySide2.QtCore import  Qt

## Sqlalchemy to QT Table adapter
# Acts as a model of a sqlalchemy object to a QSqlTableModel.  Allows for sorting,
# column headers
class SqlalchemyModel(QSqlTableModel):


    ## Constructor for the model
    # @param session sqlalchemy session object
    # @param clazz sqlalchemy Base class instance
    # @param cols tuple of ( columnName, sqlObjectMember, stringColumnName, miscInfo )
    # @param orderBy sqlalchemy expression for sorting rows on query
    # @param sort UNIMPLEMENTED for clicking on table header, tuple in the form (columnNumber, order ), unimplemented
    # Example
    # <pre>
    # sqlalchemy_model.SqlalchemyModel(
    # session,
    # db.Crash,
    # [
    #     ('Time',            db.Crash.timestamp,                 'timestamp', {}),
    #     ('RunID',           db.Crash.runid,                     'runid', {} ),
    #     ('Reason',          db.Crash.crashReason,               'crashReason', {}),
    #     ('Exploitability',  db.Crash.exploitability,            'exploitability', {}),
    #     ('Ranks',           db.Crash.ranksString,               'ranksString', {}),
    #     ('Crashash',        db.Crash.crashash,                  'crashash', {}),
    #     ('Crash Address',   db.Crash.crashAddressString,        'crashAddressString', {}),
    #     ('IP',              db.Crash.instructionPointerString,  'instructionPointerString', {}),
    #     ('Stack Pointer',   db.Crash.stackPointerString,        'stackPointerString', {}),
    # ],
    # orderBy=desc(db.Crash.timestamp) )
    # </pre>
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

    ## QT TableModel method for returning horizontal and vertical headers
    # @param section Basically a 0-based column index
    # @param orientation Horizontal or vertical columns
    # @param role Use of the data, stick with the Qt.DisplayRole or else you'll get weird results
    def headerData( self, section, orientation, role ):
        try:
            ret = self.cols[section][0]
        except:
            return None

        if role!=Qt.DisplayRole or orientation!=Qt.Horizontal:
            return None

        return ret

    ## Flags about the cell, is it enabled?  Selectable?
    def flags(self, i):
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


    ## Updates table
    def update(self):
        self.layoutAboutToBeChanged.emit()

        self.rows = self.session.query( self.clazz ).\
            order_by(self.orderBy).\
            all()
        self.layoutChanged.emit()

    ## Return number of rows
    # @param parent parent window
    def rowCount(self, parent):
        return len(self.rows)

    ## Returns number of columns
    # @param parent parent window
    def columnCount(self, parent):
        return len(self.cols)

    ## Returns data for a cell
    # @param index indices for row and column
    # @param role Stick with the Qt.DisplayRole
    def data(self, index, role ):
        # If we return stuff on other roles we get weird
        # check boxes in the cells
        if role==Qt.DisplayRole:
            row = self.rows[ index.row() ]
            name = self.cols[ index.column() ][2]

            ret = getattr(  row, name )
            ret = str(ret)
            return ret
        ## This the custom role when a user clicks, return the entire row
        if role==Qt.UserRole:
            return self.rows[ index.row() ]

        return  None

    ## Unimplemented but should be used to click on column header and sort
    def sort( self, col, order ):
        self.sort = (col, order)
        self.update()

    ## Unimplemented, we don't want to change results yet
    def setData( self, index, value, role ):
        pass