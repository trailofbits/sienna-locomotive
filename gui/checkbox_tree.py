from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem
from PyQt5.QtCore import pyqtSignal, Qt


class CheckboxTreeWidgetItem(QTreeWidgetItem):

    def __init__(self, parent, *args):
        super().__init__(parent, *args)
        self._parent = parent
        self.setCheckState(0, Qt.Unchecked)

    def setData(self, column, role, value):
        should_emit = (role == Qt.CheckStateRole) and \
                      (column == 0) and \
                      (self.data(column, role) is not None) and \
                      (self.checkState(0) != value)
        super().setData(column, role, value)
        if should_emit:
            parent = self._parent
            if type(parent) is CheckboxTreeWidget:
                parent.itemCheckedStateChanged.emit(self, 0, True if self.checkState(0) == Qt.Checked else False)


class CheckboxTreeWidget(QTreeWidget):

    itemCheckedStateChanged = pyqtSignal(CheckboxTreeWidgetItem, int, bool)

    def __init__(self, *args):
        super().__init__(*args)
