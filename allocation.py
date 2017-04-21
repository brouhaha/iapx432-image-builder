#!/usr/bin/python3
# Allocation map for Intel iAPX 432 utilities

# Copyright 2014, 2015, 2016, 2017 Eric Smith <spacewar@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU General Public License
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

class Allocation(object):
    # This could be eight times as storage-efficient, at a substantial
    # increase in complexity, by storing eight bits per byte instead
    # of only one.
    class AllocationError(Exception):
        pass
    
    def __init__(self, size, name = None):
        self.name = name
        self.size = size
        self._v = bytearray(size)
        self._z = bytearray(size)  # in Python 3, this could be a bytes object
        self._ff = bytearray([0xff])

    def __str__(self):
        return ' '.join(["%d" % b for b in self._v])

    def allocate(self, size=1, pos=0, fixed=False, dry_run=False):
        debug = False # self.name == 'object_table_directory'
        if debug:
            print("allocating from:", self.name, "size:", size, "pos:", pos, "fixed:", fixed, "dry_run:", dry_run)
        if not fixed:
            pos = self._v.find(self._z[:size], pos)
            if pos < 0:
                raise self.AllocationError('negative pos')
            if pos + size > self.size:
                raise self.AllocationError('pos %d + size %d > allocation size %d' % (pos, size, self.size))
        if self._v[pos:pos+size] != self._z[:size]:
            #print("pos:", pos, "size:", size)
            #print([int(x) for x in self._v[pos:pos+size]])
            raise self.AllocationError('pos %d size %d already allocated' % (pos, size))
        if not dry_run:
            self._v[pos:pos+size] = [0xff] * size
        if debug:
            print("returning pos", pos)
        return pos

    #def find_space(self, size=1, pos=0, fixed=False):
    #    return self.allocate(size=size, pos=pos, fixed=fixed, dry_run=True)

    def highest_allocated(self):
        return len(self._v.rstrip(self._z[0:1])) - 1

    def discontiguous(self):
        # XXX
        return False


