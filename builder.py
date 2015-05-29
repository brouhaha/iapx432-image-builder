#!/usr/bin/python2

# Copyright 2014, 2015 Eric Smith <spacewar@gmail.com>

import argparse
import pprint
import re
import sys
import xml.etree.ElementTree

from arch import arch


class Allocation(object):
    # This could be eight times as storage-efficient, at a substantial
    # increase in complexity, by storing eight bits per byte instead
    # of only one.
    
    def __init__(self, size):
        self._v = bytearray(size)
        self._z = bytearray(size)  # in Python 3, this could be a bytes object

    def __str__(self):
        return ' '.join(["%d" % b for b in self._v])

    def allocate(self, size=1, pos=None, fixed=False, dry_run=False):
        if pos is None:
            assert fixed == False
            pos = self._v.find(self._z[:size])
            assert pos != -1
        elif not fixed:
            pos = self._v.find(self._z[:size], pos)
            assert pos != -1
        assert self._v[pos] == 0
        if not dry_run:
            self._v[pos:pos+size] = [1] * size
        return pos

    def lowest_available(self, size=1):
        pos = self._v.find(self._z)
        assert pos != -1
        return pos


class Field(object):
    # a factory method
    @staticmethod
    def parse(segment, field_tree):
        d = { 'ad': AD,
              'field' : DataField }
        return d[field_tree.tag](segment, field_tree)

    def __init__(self, segment, field_tree):
        self.segment = segment
        self.image = segment.image
        self.arch = self.image.arch
        self.name = field_tree.get('name')
        self.size = None
        self.offset = None
        # XXX

    def compute_size(self):
        if self.size is None:
            # XXX hack:
            self.size = 4
        return self.size


class AD(Field):
    _rights_dict = { 'true': True,
                     '1': True,
                     'false': False,
                     '0': False }

    def _get_rights(self, ad_tree, right, default = True):
        return self._rights_dict.get(ad_tree.get(right), default)
        
    def __init__(self, segment, ad_tree):
        assert segment.base_type == 'access_segment'
        assert len(ad_tree) == 0
        super(AD, self).__init__(segment, ad_tree)
        self.size = 4

        self.segment_name = ad_tree.get('segment')

        self.valid      =  self._get_rights(ad_tree, 'valid',  default = self.segment_name is not None)
        self.write      =  self._get_rights(ad_tree, 'write',  default = True)
        self.read       =  self._get_rights(ad_tree, 'read',   default = True)
        self.heap       =  self._get_rights(ad_tree, 'heap',   default = False)
        self.delete     =  self._get_rights(ad_tree, 'delete', default = True)
        self.sys_rights = [self._get_rights(ad_tree, 'sys1',   default = False),
                           self._get_rights(ad_tree, 'sys2',   default = False),
                           self._get_rights(ad_tree, 'sys3',   default = False)]

        self.dir_index = None
        self.seg_index = None

    def write_value(self):
        if self.valid:
            if self.dir_index is None:
                assert self.segment_name in self.image.descriptor_by_name
                segment = self.image.descriptor_by_name[self.segment_name]
                self.dir_index = segment.dir_index
                self.seg_index = segment.seg_index
            # XXX write value
            pass
        else:
            # XXX write zeros
            pass

class DataField(Field):
    def __init__(self, segment, field_tree):
        assert segment.base_type == 'data_segment'
        super(DataField, self).__init__(segment, field_tree)

    def write_value(self):
        # XXX
        pass


# XXX add a factory method parse()
class Descriptor(object):
    def __init__(self, image, tree):
        self.image = image
        self.arch = image.arch
        self.name = tree.get('name')

    def _set_dir_index(self, dir_index):
        if self.dir_index is not None:
            assert dir_index == self.dir_index
        else:
            self.dir_index = dir_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                coord = (self.dir_index, self.seg_index)
                assert coord not in self.image.descriptor_by_coord
                self.image.descriptor_by_coord[coord] = self

    def _set_seg_index(self, seg_index):
        if self.seg_index is not None:
            assert seg_index == self.seg_index
        else:
            self.seg_index = seg_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                coord = (self.dir_index, self.seg_index)
                assert coord not in self.image.descriptor_by_coord
                self.image.descriptor_by_coord[coord] = self

    def assign_coordinates(self):
        pass


class Segment(Descriptor):
    def __init__(self, image, segment_tree):
        super(Segment, self).__init__(image, segment_tree)
        self.segment_type = segment_tree.get('type')
        assert self.segment_type in self.arch.symbols
        st = self.arch.symbols[self.segment_type]
        assert st.type == 'segment'
        self.system_type = st.value.system_type
        self.base_type = st.value.base_type

        self.min_size = 0
        self.phys_addr = None
        self.size = None

        self.min_size = segment_tree.get('min_size')
        #self.phys_addr = segment_tree.get('phys_addr')  # address of segment prefix
        self.dir_index = None
        self.seg_index = None

        self.written = False

        self.fields = []
        for field_tree in segment_tree:
            self.fields.append(Field.parse(self, field_tree))
        print "%d fields" % len(self.fields)

    def compute_size(self):
        offset = 0
        self.data = bytearray(65536)
        self.allocation = Allocation(65536)

        for field in self.fields:
            field.compute_size()
            # hack - we really need the sizes computed!
            if field.size is None:
                field.size = 4

        for field in self.fields:
            if field.offset is not None:
                offset = field.offset
                self.allocation.allocate(pos = field.offset, size = field.size, fixed=True)
            else:
                
                field.offset = self.allocation.allocate(pos = field.offset, size = field.size)
            offset = field.offset + field.size

        self.size = max(self.allocation.allocate(dry_run=True), self.min_size)
        return self.size

    def write_to_image(self):
        if self.written:
            return
        for field in self.fields:
            field.write_value()
        self.written = True


class AccessSegment(Segment):
    def __init__(self, image, segment_tree):
        super(AccessSegment, self).__init__(image, segment_tree)


class DataSegment(Segment):
    def __init__(self, image, segment_tree):
        super(DataSegment, self).__init__(image, segment_tree)


class SegmentTable(DataSegment):
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


class Refinement(Descriptor):
    def __init__(self, image, descriptor_tree):
        super(Refinement, self).__init__(image, descriptor_tree)


class ExtendedType(Descriptor):
    def __init__(self, image, descriptor_tree):
        super(Refinement, self).__init__(image, descriptor_tree)


class Image(object):
    class InvalidDescriptorTypeError(Exception):
        def __init__(self, descriptor_tree):
            print descriptor_tree
            self.msg = 'invalid descriptor type "%s"' % descriptor_tree.tag

    # XXX convert to a Descriptor factory staticmethod
    def parse_descriptor(self, descriptor_tree):
        descriptor_type = descriptor_tree.tag
        descriptor_name = descriptor_tree.get('name')
        assert descriptor_name not in self.descriptor_by_name
        if descriptor_type == 'segment':
            segment_type = descriptor_tree.get('type')
            object_table_name = descriptor_tree.get('object_table')
            if segment_type == 'object_table_data_segment':
                if descriptor_name == object_table_name:
                    assert self.segment_table_directory is None
                    segment = SegmentTableDirectory(self, descriptor_tree)
                    self.segment_table_directory = segment
                else:
                    segment = SegmentTable(self, descriptor_tree)
            else:
                segment = Segment(self, descriptor_tree)
            self.descriptor_by_name[descriptor_name] = segment
        elif descriptor_type == 'refinement':
            refinement = Refinement(self, descriptor_tree)
            self.descriptor_by_name[descriptor_name] = refinement
        elif descriptor_type == 'extended_type':
            extended_type = ExtendedType(self, descriptor_tree)
            self.descriptor_by_name[descriptor_name] = extended_type
        else:
            raise self.InvalidDescriptorType(descriptor_tree)
        print "%s '%s'" % (descriptor_type, descriptor_name)

    def __init__(self, arch, image_tree):
        self.arch = arch
        image_root = image_tree.getroot()
        assert image_root.tag == 'image'
        self.descriptor_by_coord = { }
        self.descriptor_by_name = { }
        self.segment_table_directory = None

        for descriptor_tree in image_root:
            self.parse_descriptor(descriptor_tree)

        # compute sizes of all segments
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, Segment):
                descriptor.compute_size()

        # assign coordinates to all segment tables
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, SegmentTable):
                descriptor.assign_coordinates()

        # assign coordinates to all other descriptors
        for descriptor in self.descriptor_by_name.values():
            descriptor.assign_coordinates()

        # if segment has a preassigned base address, write it
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, Segment):
                if descriptor.phys_addr is not None:
                    descriptor.write_to_image()

        # write all other segments
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, Segment):
                descriptor.write_to_image()


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

    print '%d segments in image' % len(image.descriptor_by_name)
