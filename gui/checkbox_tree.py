from PyQt5.QtWidgets import QTreeView
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtCore import pyqtSignal, Qt


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
