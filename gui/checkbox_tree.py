from PyQt5.QtWidgets import QTreeView
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtCore import pyqtSignal, Qt, QSortFilterProxyModel


class CheckboxTreeWidgetItem(QStandardItem):

    def __init__(self, parent, index, *args):
        super().__init__(*args)
        self.index = index
        self._parent = parent
        self.setCheckState(Qt.Unchecked)
        self.setCheckable(True)
        self.setEditable(False)

    def setData(self, value, role):
        should_emit = (role == Qt.CheckStateRole) and \
                      (self.data(role) is not None) and \
                      (self.checkState() != value)
        super().setData(value, role)
        if should_emit:
            parent = self._parent
            if type(parent) is CheckboxTreeWidget:
                parent.itemCheckedStateChanged.emit(self, True if self.checkState() == Qt.Checked else False)


class CheckboxTreeModel(QStandardItemModel):

    def __init__(self):
        super().__init__()


class CheckboxTreeWidget(QTreeView):

    itemCheckedStateChanged = pyqtSignal(CheckboxTreeWidgetItem, bool)

    def __init__(self, *args):
        super().__init__(*args)


class CheckboxTreeSortFilterProxyModel(QSortFilterProxyModel):

    def __init__(self, *args):
        super().__init__(*args)

    def lessThan(self, QModelIndex_l, QModelIndex_r):
        """ Convert strings to ints before sorting (if possible) """
        try:
            left = self.sourceModel().data(QModelIndex_l)
            right = self.sourceModel().data(QModelIndex_r)

            return int(left) < int(right)
        except ValueError:
            return super().lessThan(QModelIndex_l, QModelIndex_r)

    def filterAcceptsRow(self, p_int, QModelIndex):
        """ Keep child rows when we filter on the top-level items """
        super_accepts = super().filterAcceptsRow(p_int, QModelIndex)
        accepts_parent = super().filterAcceptsRow(QModelIndex.row(), self.parent(QModelIndex))
        is_child = QModelIndex.row() != -1 and p_int == 0

        return super_accepts or (is_child and accepts_parent)
