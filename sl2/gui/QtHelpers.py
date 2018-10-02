from PySide2.QtCore import QObject, Signal


## class QIntVariable
#  Helper class that binds a variable to a value and provides a signal that can automatically update
#  bindings when the variable changes.
class QIntVariable(QObject):
    ## Signal that fires when the value is updated - contains the new value
    valueChanged = Signal(int)

    def __init__(self, value):
        QObject.__init__(self)
        self.value = value

    ## Increase the value by one
    def increment(self):
        self._update(self.value + 1)

    ## Set a new value
    def _update(self, newval):
        self.value = newval
        self.valueChanged.emit(self.value)


## class QFloatVariable
#  Sama as QIntVariable, but for Floats
class QFloatVariable(QObject):
    ## Signal that fires when the value is updated - contains the new value
    valueChanged = Signal(float)

    def __init__(self, value):
        QObject.__init__(self)
        self.value = value

    ## Set a new value
    def update(self, newval):
        self.value = newval
        self.valueChanged.emit(self.value)


## class QTextAdapter
#  Takes a format string and a set of variables and automatically updates the rendered string whenever one of the
#  variables changes.
class QTextAdapter(QObject):
    """ Text adapter - pass a format string and a set of variables and bind .update to each of the variables
        valueChanged signals """
    ## Signal that fires when the value is updated - contains the new value
    updated = Signal(str)

    def __init__(self, format_str, *args):
        QObject.__init__(self)
        self.format_str = format_str
        self.args = args

    def __str__(self):
        return self.format_str.format(*self.args)

    ## Emit the rendered string
    def update(self, *_throwaway):
        self.updated.emit(str(self))
