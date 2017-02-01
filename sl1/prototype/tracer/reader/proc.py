#!/usr/bin/env python


class Proc(object):

  class Mapping(object):

    @classmethod
    def from_proc_line(cls, line):
      lst = line.split()
      (address, perms, offset, dev, inode), path = lst[:5], lst[5:]
      mapping = cls()
      mapping.range = [int(addr, 16) for addr in address.split('-')]
      mapping.address = mapping.range[0]
      mapping.size = mapping.range[1] - mapping.range[0]
      mapping.perms = perms
      mapping.offset = int(offset, 16)
      mapping.dev = [int(n) for n in dev.split(':')]
      mapping.inode = int(inode)
      mapping.path = path[0].strip() if path else None
      return mapping

    @classmethod
    def from_proc_maps(cls, pid):
      if not pid:
        pid = 'self'
      mapsfile = '/proc/%s/maps' % (pid,)
      mappings = []
      for line in open(mapsfile, 'r'):
        mappings.append(cls.from_proc_line(line))
      return mappings

    def has_address(self, addr):
      return addr >= self.range[0] and addr < self.range[1]

    def __repr__(self):
      return '<%s (%x, %d)>'%(self.path, self.address, self.size)

  def __init__(self, pid = None):
    self._maps = Proc.Mapping.from_proc_maps(pid)

  def find_map_by_address(self, address):
    try:
      return next(m for m in self._maps if m.has_address(address))
    except StopIteration:
      return None


if __name__=='__main__':
  p = Proc()
  print p.find_map_by_address(34)
  a = p._maps[0].range[0]
  print p.find_map_by_address(a)


