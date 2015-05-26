#!/usr/bin/python2

# Copyright 2014, 2015 Eric Smith <spacewar@gmail.com>

import argparse
import collections
import pprint
import re
import sys
import xml.etree.ElementTree

from arch import arch


class Allocation(object):
    # This could be eight times as storage-efficient, at a substantial
    # increase in complexity, by storing eight bits per byte instead
    # of only one.
    _z = bytearray([0])  # in Python 3, this could be a bytes object
    
    def __init__(self, size):
        self._v = bytearray(size)

    def __str__(self):
        return ' '.join(["%d" % b for b in self._v])

    def allocate(self, pos=None, size=1, subsequent=False):
        if pos is None:
            pos = self._v.find(self._z)
            assert pos != -1
        elif subsequent:
            pos = self._v.find(self._z, pos)
            assert pos != -1
        assert self._v[pos] == 0
        self._v[pos] = 1
        return pos

    def lowest_available(self):
        pos = self._v.find(self._z)
        assert pos != -1
        return pos


class Field(object):
    def __init__(self, image, field_tree):
        self._image = image
        self._arch = image.arch
        self.size = None
        self.offset = None
        # XXX

    def compute_size(self):
        # XXX
        return 0


class Segment(object):
    _seg_allocation = table_by_seg_index = { }
    _segment_by_coord = { }
    
    def _set_dir_index(self, dir_index):
        if self.dir_index is not None:
            assert dir_index == self.dir_index
        else:
            self.dir_index = dir_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                coord = (self.dir_index, self.seg_index)
                assert coord not in type(self)._segment_by_coord
                type(self)._segment_by_coord[coord] = self

    def _set_seg_index(self, seg_index):
        if self.seg_index is not None:
            assert seg_index == self.seg_index
        else:
            self.seg_index = seg_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                coord = (self.dir_index, self.seg_index)
                assert coord not in type(self)._segment_by_coord
                type(self)._segment_by_coord[coord] = self

    def __init__(self, image, segment_tree):
        self._image = image
        self._arch = image.arch
        self.name = segment_tree.get('name')
        self.segment_type = segment_tree.get('type')
        assert self.segment_type in self._arch.symbols
        st = self._arch.symbols[self.segment_type]
        assert st.type == 'segment'
        self.system_type = st.value.system_type
        self.base_type = st.value.base_type

        self.min_size = 0
        self.phys_addr = None
        self.size = None

        #self.min_size = segment_tree.get('min_size')
        #self.phys_addr = segment_tree.get('phys_addr')  # address of segment prefix
        self.dir_index = None
        self.seg_index = None

        self.written = False

        self.fields = []
        for field_tree in segment_tree:
            self.fields.append(Field(self._image, field_tree))
        print "%d fields" % len(self.fields)

    def assign_coordinates(self):
        pass

    def compute_size(self):
        self.data = bytearray(65536)
        self.allocation = Allocation(65536)

        for field in self.fields:
            field.compute_size()

        # first handle any fields at known offsets
        for field in self.fields:
            if field.offset is not None:
                self.allocation.allocate(pos = field.offset, size = field.size)

        # allocate remaining fields
        for field in self.fields:
            if field.offset is None:
                field.offset = self.allocation.allocate(pos = 0, subsequent = True, size = field.size)

        self.size = max(self.allocation.lowest_available(), self.min_size)
        return self.size

    def write_to_image(self):
        if self.written:
            return
        # XXX more code needed here
        self.written = True



class SegmentTable(Segment):
    def __init__(self, image, segment_tree):
        super(SegmentTable, self).__init__(image, segment_tree)
        self._index_allocation = Allocation(4096)
        self.dir_index = 2

class SegmentTableDirectory(SegmentTable):
    def __init__(self, image, segment_tree):
        super(SegmentTableDirectory, self).__init__(image, segment_tree)
        self.seg_index = 2
        if self.phys_addr is None:
            self.phys_addr = 0  # address of segment prefix
        else:
            assert self.phys_addr == 0


class Image(object):
    def parse_segment(self, segment_tree):
        segment_name = segment_tree.get('name')
        print "segment '%s'" % segment_name
        assert segment_name not in self.segment_by_name
        segment_type = segment_tree.get('type')
        object_table_name = segment_tree.get('object_table')
        if segment_type == 'object_table_data_segment':
            if segment_name == object_table_name:
                assert self.segment_table_directory is None
                segment = SegmentTableDirectory(self, segment_tree)
                self.segment_table_directory = segment
            else:
                segment = SegmentTable(self, segment_tree)
        else:
            segment = Segment(self, segment_tree)
        self.segment_by_name[segment_name] = segment

    def __init__(self, arch, image_tree):
        self.arch = arch
        image_root = image_tree.getroot()
        assert image_root.tag == 'image'
        self.segment_by_name = {}
        self.segment_table_directory = None

        for segment_tree in image_root:
            assert segment_tree.tag == 'segment'
            self.parse_segment(segment_tree)

        # compute sizes of all segments
        for segment in self.segment_by_name.values():
            segment.compute_size()

        # assign coordinates to all segment tables
        for segment in self.segment_by_name.values():
            if type(segment) == SegmentTable:
                segment.assign_coordinates()

        # assign coordinates to all other segments
        for segment in self.segment_by_name.values():
            segment.assign_coordinates()

        # if segment has a preassigned base address, write it
        for segment in self.segment_by_name.values():
            if segment.phys_addr is not None:
                segment.write_to_image()

        # write all other segments
        for segment in self.segment_by_name.values():
            segment.write_to_image()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='iAPX 432 Image Builder')
    arg_parser.add_argument('-a', '--arch',
                            type=argparse.FileType('r', 0),
                            default='definitions.xml',
                            help='architecture definition (XML)')
    arg_parser.add_argument('image',
                            type=argparse.FileType('r', 0),
                            nargs=1,
                            help='image definition (XML)')

    args = arg_parser.parse_args()

    arch_tree = xml.etree.ElementTree.parse(args.arch)
    args.arch.close()
    arch = arch(arch_tree)

    image_tree = xml.etree.ElementTree.parse(args.image[0])
    args.image[0].close()
    image = Image(arch, image_tree)

    print '%d segments in image' % len(image.segment_by_name)
