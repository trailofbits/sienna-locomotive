from PySide2.QtCore import QObject, Signal

class QIntVariable(QObject):
    valueChanged = Signal(int)

    def __init__(self, value):
        QObject.__init__(self)
        self.value = value

    def increment(self):
        self._update(self.value + 1)

    def _update(self, newval):
        self.value = newval
        self.valueChanged.emit(self.value)


class QFloatVariable(QObject):
    valueChanged = Signal(float)

    def __init__(self, value):
        QObject.__init__(self)
        self.value = value

    def update(self, newval):
        self.value = newval
        self.valueChanged.emit(self.value)


class QTextAdapter(QObject):
    """ Text adapter - pass a format string and a set of variables and bind .update to each of the variables
        valueChanged signals """
    updated = Signal(str)

    def __init__(self, format_str, *args):
        QObject.__init__(self)
        self.format_str = format_str
        self.args = args

    def __str__(self):
        return self.format_str.format(*self.args)

    def update(self, *_throwaway):
        self.updated.emit(str(self))