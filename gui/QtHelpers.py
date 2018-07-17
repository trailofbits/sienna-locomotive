from PyQt5.QtCore import QObject, pyqtSignal


class hasValueChanged(type):
    """ Metaclass that dynamically creates a class with the correct type of valueChanged signal """
    def __new__(mcs, classname, bases, dct):
        if 't' in dct:
            dct['valueChanged'] = pyqtSignal(dct['t'])
        return type.__new__(mcs, classname, bases, dct)


class QGenericVariable(QObject, metaclass=type("mergeMeta", (type(QObject), hasValueChanged), {})):
    """ Holds a variable of type t and emits the valueChanged signal when the variable is updated """
    t = type(None)

    def __init__(self, value):
        QObject.__init__(self)
        self.value = value

    def update(self, new_val):
        self.value = new_val
        self.valueChanged.emit(self.value)


QIntVariable = type("QIntVariable", (QGenericVariable,), {'t': int,
                                                          'increment': (lambda self: self.update(self.value + 1))})
QFloatVariable = type("QFloatVariable", (QGenericVariable,), {'t': float})


class QTextAdapter(QObject):
    """ Text adapter - pass a format string and a set of variables and bind .update to each of the variables
        valueChanged signals """
    updated = pyqtSignal(str)

    def __init__(self, format_str, *args):
        QObject.__init__(self)
        self.format_str = format_str
        self.args = args

    def __str__(self):
        return self.format_str.format(*self.args)

    def update(self, *_throwaway):
        self.updated.emit(str(self))