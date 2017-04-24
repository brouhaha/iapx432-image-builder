#!/usr/bin/python3
# Allocation map by ranges for Intel iAPX 432 utilities

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

from enum import Enum, unique

import attr
from sortedcontainers import SortedList


@attr.s
class Block:
    """
    Used internally to Allocation to represent a block of memory.
    Not part of public API.
    """
    addr      = attr.ib(cmp = True,  hash = True)
    size      = attr.ib(cmp = False, hash = False)
    data      = attr.ib(cmp = False, hash = False, default = None)
    free      = attr.ib(cmp = False, hash = False, default = False)
    prev_free = attr.ib(cmp = False, hash = False, default = None)
    next_free = attr.ib(cmp = False, hash = False, default = None)


class AllocationError(Exception):
    pass


class AllocationPolicy(Enum):
    FIRST_FIT = 1
    ROTATING_FIRST_FIT = 2


class Allocation:
    def __init__(self, size: int, name: str = None, policy = AllocationPolicy.FIRST_FIT):
        if size < 1:
            raise ValueError('requested size is negative or zero')

        self._size       = size
        self._name       = name
        self._policy     = policy

        self._total_free = size
        self._first_free = 0	# start addr of first (lowest addr) free block
        self._next_free  = 0	# start addr of next free block to consider
                                # for allocation

        block = Block(addr = 0,
                      size = size,
                      free = True)

        self._blocks = SortedList([block], key = lambda b: b.addr)


    def _dump(self):
        """
        Dump debugging information including the block list.
        """
        print('first free:', self._first_free)
        print('next free:', self._next_free)
        for b in self._blocks:
            print(b)


    def _find_block(self, addr: int, exact: bool = False, require_free: bool = False):
        """
        Find the block that contains a particular address, optionally
        reqiring exactly matching the start address, and optionally requiring
        the block to be free.
        """
        i = self._blocks.bisect_key_right(addr)
        b = self._blocks[i-1]
        if exact:
            assert b.addr == addr
        if require_free:
            assert b.free
        return b
        

    def _split_free_block(self, addr: int, size: int):
        """
        Given the address of a free block and a size, split that block into
        two blocks, the first of which will be of the specified size.
        """
        b = self._find_block(addr, exact = True, require_free = True)
        assert size < b.size
        nb = Block(addr = addr + size,
                   size = b.size - size,
                   data = b.data,
                   free = b.free,
                   prev_free = addr,
                   next_free = b.next_free)
        b.size = size
        b.next_free = nb.addr
        self._blocks.add(nb)


    def _allocate_block(self, addr: int, data):
        """
        Given the address of a free block, allocate the block.
        """
        b = self._find_block(addr, exact = True, require_free = True)

        self._total_free -= b.size

        if b.prev_free is not None:
            pb = self._find_block(b.prev_free, exact = True)
            pb.next_free = b.next_free
        else:
            self._first_free = b.next_free

        if b.next_free is not None:
            nb = self._find_block(b.next_free, exact = True)
            nb.prev_free = b.prev_free
        else:
            nb = None

        if self._next_free == addr:
            if nb is not None:
                self._next_free = nb.addr
            else:
                self._next_free = None
        
        b.free = False
        b.prev_free = None
        b.next_free = None
        
        b.data = data


    def find_free(self, size: int, addr: int = None) -> int:
        """
        Finds free space of a requested size. If addr is not none,
        only attempts to find free space starting at that address.

        Args:
            size:   The amount of free space to find
            addr:   The address at which to find free space

        Returns:
            An int the address at which the requested amount of space was found.

        Raises:
            AllocationError

        If a call to find_free() without an address argument is
	successful, and is immediately followed by a call to
	allocate() for the same size, the allocation will occur at the
	address returned by find_free().
        """

        if addr is not None:
            if addr < 0:
                raise ValueError('requested address is negative')
            if addr + size > self._size:
                raise ValueError('requested block extends beyond address space.')

            b = self._find_block(addr)
            assert addr >= b.addr
            return b.free and addr + size <= b.addr + b.size

        if size < 0:
            raise ValueError('requested size is negative')
        if size > self._size:
            raise ValueError('requested size is larger than address space')
        
        second_pass = False
        while True:
            if self._policy == AllocationPolicy.ROTATING_FIRST_FIT:
#                i = self._blocks.bisect_key_right(self._next_free)
#                b = self._blocks[i-1]
                b = self._find_block(self._next_free, require_free = True)
            else:
                b = self._find_block(self._first_free, require_free = True)
            if b.size >= size:
                addr = b.addr
                break
            self._next_free = b.next_free
            if self._next_free is None:
                if second_pass or self._policy == AllocationPolicy.FIRST_FIT:
                    raise AllocationError('insufficient contiguous free space available')
                self._next_free = self._first_free
                second_pass = True
                continue
        return addr


    def allocate(self, size: int, data = None, addr: int = None) -> int:
        """
        Allocate the reqeusted amount of space, optionally at a specific
        address. Optionally associate some data with the space.
        """
        debug = False

        if debug:
            print("allocating from:", self.name, "size:", size, "addr:", addr)

        if size < 0:
            raise ValueError('requested size is negative')
        if size > self._size:
            raise ValueError('requested size is larger than address space')
        if addr is not None:
            if addr < 0:
                raise ValueError('requested address is negative')
            if addr + size > self._size:
                raise ValueError('requested block extends beyond address space.')

        if size > self._total_free:
            raise AllocationError('insufficient free space available')

        # If explicit address is not supplied, search free list for a
        # sufficiently large free block.
        if addr is None:
            addr = self.find_free(size)

        while True:
            i = self._blocks.bisect_key_right(addr)
            b = self._blocks[i-1]
            if not b.free:
                raise AllocationError('requested address is allocated')
            if addr + size > b.addr + b.size:
                raise AllocationError('insufficient space available at requested address')

            if addr > b.addr:
                # split block at beginning
                if debug:
                    print('splitting block at beginning')
                self._split_free_block(b.addr, addr - b.addr)
                if debug:
                    self._dump()
                continue

            if size < b.size:
                # split block at end
                if debug:
                    print('splitting block at end')
                self._split_free_block(b.addr, size)
                if debug:
                    self._dump()
                continue

            # we now have exact match, change block from free to allocated
            if debug:
                print('have match, allocating')
            self._allocate_block(addr, data)
            break
            
        return addr


    def free_space(self, addr: int = 0, size: int = None):
        """
        Returns the amount of free space available within an address
        range, which defaults to the entire address space.
        """
        if size is None:
            size = self._size - addr
        if addr < 0:
            raise ValueError('requested address is negative')
        if addr + size > self._size:
            raise ValueError('requested range extends beyond address space.')

        #if addr == 0 and size == self._size:
        #    return self._total_free

        sa = addr
        count = 0
        b = self._find_block(sa)
        sa += b.size
        if b.free:
            count += b.size - (b.addr - addr)
        while addr + size > b.addr + b.size:
            b = self._find_block(sa)
            sa += b.size
            if b.free:
                if addr + size >= b.addr + b.size:
                    count += b.size
                else:
                    count += (addr + size) - b.addr
        return count


    def allocated_space(self, addr: int = 0, size: int = None):
        """
        Returns the amount of allocated space within an address
        range, which defaults to the entire address space.
        """
        if size is None:
            size = self._size - addr
        if addr < 0:
            raise ValueError('requested address is negative')
        if addr + size > self._size:
            raise ValueError('requested range extends beyond address space.')
        return size - self.free_space(addr, size)


    def last_free_range(self) -> int:
        """
        Return the address of the start of the last free block, which
        is one past the end of the last allocated block, if there is one.
        If there are no allocated blocks, the returned value will be zero.
        If the entire address space is allocated, the returned value will
        be the size of the address space.
        """
        b = self._blocks[-1]  # guaranteed to be at least one block, which
        # could be free if nothing is allocated
        if b.free:
            try:
                b = self._blocks[-2]
                assert not b.free  # can't have to consecutive free blocks
            except IndexError:
                return 0
        return b.addr + b.size


    def contiguous_from_zero(self):
        ff = self.find_free(1)
        lf = self.last_free_range()
        return ff == lf
