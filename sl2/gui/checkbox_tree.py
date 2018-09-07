from PySide2.QtWidgets import QTreeView, QComboBox, QStyledItemDelegate
from PySide2.QtGui import QStandardItem, QStandardItemModel
from PySide2.QtCore import Signal, Qt, QSortFilterProxyModel

mode_labels = {1 << 0: "Nth Call",
               1 << 1: "Return Address",
               1 << 2: "Argument Hash",
               1 << 3: "Argument Comparison",
               1 << 4: "Fuzzy",
               1 << 5: "Hybrid",
               1 << 6: "High Precision",
               1 << 7: "Filename Comparison",
               1 << 8: "Nth Call @ Address"}


# Inverse mapping so we can cheaply get bit flags out of text labels
# mode_labels.update(dict(reversed(item) for item in mode_labels.items()))


class ComboboxTreeItemDelegate(QStyledItemDelegate):

    def __init__(self, adapter, *args):
        super().__init__(*args)
        self.adapter = adapter
        self.combobox = None

    def createEditor(self, parent, option, index):
        self.combobox = QComboBox(parent)
        for sft in [4, 5, 6]:
            self.combobox.addItem(mode_labels[1 << sft], 1 << sft)

        return self.combobox

    def setEditorData(self, editor, index):
        val = index.model().data(index, role=Qt.UserRole)
        self.combobox.setCurrentText(mode_labels[val])

    def setModelData(self, editor, model, index):
        model.setData(index, self.combobox.currentData(), role=Qt.UserRole)
        model.setData(index, self.combobox.currentText())
        self.adapter.update(model.data(index, role=Qt.UserRole + 1), mode=self.combobox.currentData())


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
