#!/usr/bin/python

# b = bitarray(size)
# b = bitarray(size, from_bytes=bytearray, bit_offset=3)

# When a bitarray is interpreted as an integer, the bit at index 0 is the
# LSB, and the bit at the highest index is the MSB.  The weight of the
# bit at index i is thus 2**i (except MSB in signed interpretation)

from __future__ import division
from __future__ import print_function
from collections import Sequence, MutableSequence

class bitarray(MutableSequence):
    def __init__(self, len):
        self._len = len
        self._bits = bytearray((self._len + 7) // 8)
        # super().__init__()

    def __getitem__(self, key):
        if isinstance(key, int):
            if key < 0:
                key = self._len - key
            if not 0 <= key < self._len:
                raise IndexError
            return (self._bits[key // 8] >> (key % 8)) & 1
        if isinstance(key, slice):
            start = key.start if key.start is not None else 0
            stop = key.stop if key.stop is not None else self._len
            if (key.step is not None or
                start < 0 or
                stop > self._len):
                raise IndexError
            if stop < start:
                return bitarray(0)  # empty slice
            start_i = start // 8
            stop_i = (stop + 7) // 8
            return bitarray(stop - start,
                            from_bytes = self._bits[start_i : stop_i],
                            bit_offset = start % 8)
        raise TypeError

    def __setitem__(self, key, value):
        if isinstance(key, int):
            if key < 0:
                key = self._len - key
            if not 0 <= key < self._len:
                raise IndexError
            if value:
                self._bits[key // 8] |= (1 << (key % 8))
            else:
                self._bits[key // 8] &= ~ (1 << (key % 8))
            return
        if not isinstance(key, slice):
            raise TypeError
        start = key.start if key.start is not None else 0
        stop = key.stop if key.stop is not None else self._len
        if (key.step is not None or
            start < 0 or
            stop > self._len):
            raise IndexError
        if stop < start:
            stop = start  # empty slice
        width = stop - start
        #if isinstance(value, bitarray):
            # try to optimize this case
        if isinstance(value, Sequence):
            if len(value) != width:
                raise ValueError
            for i in xrange(width):
                if not 0 <= value[i] <= 1:
                    raise ValueError
                self[start + i] = value[i]
        elif isinstance(value, int):
            if value < 0:
                value += (1 << width)
            if value >= (1 << width):
                raise ValueError
            i = 0
            while i < width:
                index = start + i
                if index % 8 == 0 and i + 8 <= width:
                    byte = (value >> i) & 0xff
                    self._bits[index // 8] = byte
                    i += 8
                else:
                    bit = (value >> i) & 1
                    if bit:
                        self._bits[index // 8] |= (1 << (index % 8))
                    else:
                        self._bits[index // 8] &= ~ (1 << (index % 8))
                    i += 1
        else:
            raise TypeError

    def __len__(self):
        return self._len

    def __delitem__(self, key):
        raise NotImplementedError

    def insert(self, key, value):
        raise NotImplementedError

    def as_unsigned_int(self):
        v = 0
        for i in xrange(len(self._bits) - 1, -1, -1):
            v = (v << 8) | self._bits[i]
        return v
    
    def as_signed_int(self):
        v = self.as_unsigned_int()
        if v > (1 << ((self._len - 1) - 1)):
            v -= (1 << self._len)
        return v

    def as_bytearray(self):
        if self._len % 8 != 0:
            raise IndexError
        return self._bytes

if __name__ == '__main__':
    def pba(label, x):
        print(label)
        print('  bits:', ' '.join(["%02x" % i for i in x._bits]))
        print('  unsigned:', x.as_unsigned_int())
        print('  signed:',   x.as_signed_int())

    ba = bitarray(16)
    pba('init', ba)

    ba[15] = 1
    ba[7] = 1
    ba[5] = 1
    pba('after setting bits 5, 7, 15', ba)

    ba[0:16] = 0xbeef
    pba('after setting to 0xbeef', ba)

    ba[0:16] = 16384
    pba('after setting to 16384', ba)

    ba[0:16] = 32767
    pba('after setting to 32767', ba)

    ba[0:] = -32768
    pba('after setting to -32768', ba)

    ba[0:16] = 32768
    pba('after setting to 32768', ba)

    ba[:16] = -1
    pba('after setting to -1', ba)

    ba[1:8] = [0, 0, 0, 0, 0, 0, 0]
    pba('after setting [1:8] to list of 7 zeros', ba)

    ba[1:8] = [False, True, False, True, False, True, False]
    pba('after setting [1:8] to list of 7 bools', ba)

    ba[3:6] = 0
    pba('after setting [3:6] to 0', ba)
    
