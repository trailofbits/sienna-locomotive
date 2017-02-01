#!/usr/bin/env python

from triton import *
from pintool import *


class State(object):
  def __init__(self):
    self._stack = None
    self._registers = None

  def set_stack(self, mapping):
    self._stack = mapping

  def stack(self):
    return self._stack

  def get_register(self, reg):
    return getRegisterValue(reg)

