from PySide2.QtWidgets import QTreeView, QComboBox, QStyledItemDelegate, QItemDelegate
from PySide2.QtGui import QStandardItem, QStandardItemModel
from PySide2.QtCore import Signal, Qt, QSortFilterProxyModel

mode_labels = {1: "Nth Call",
               2: "Return Address",
               4: "Argument Hash",
               8: "Argument Comparison",
               16: "Fuzzy",
               32: "Medium Precision",
               64: "High Precision"}


class ComboboxTreeItemDelegate(QStyledItemDelegate):

    def createEditor(self, parent, option, index):
        self.combobox = QComboBox(parent)
        for key in sorted(mode_labels.keys()):
            self.combobox.addItem(mode_labels[key])

        return self.combobox

    def setEditorData(self, editor, index):
        val = index.model().data(index)
        self.combobox.setCurrentText(val)


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

    itemCheckedStateChanged = Signal(CheckboxTreeWidgetItem, bool)

    def __init__(self, *args):
        super().__init__(*args)


class CheckboxTreeSortFilterProxyModel(QSortFilterProxyModel):

    def __init__(self, *args):
        self.inverted = False
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

        if self.inverted:
            super_accepts = not super_accepts
            accepts_parent = not accepts_parent

        return super_accepts or (is_child and accepts_parent)

    def setFilterFixedString(self, p_str):
        if len(p_str) > 0 and p_str[0] == '!':
            self.inverted = True
            super().setFilterFixedString(p_str[1:])
        else:
            self.inverted = False
            super().setFilterFixedString(p_str)
