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
        if field_tree is not None:
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
    _bool_dict = { 'true': True,
                     '1': True,
                     'false': False,
                     '0': False }

    def _parse_name(self, k, v):
        # can have name or index, but if both, must match
        # XXX look up name to get index
        pass

    def _parse_index(self, k, v):
        # can have name or index, but if both, must match
        pass

    def _parse_segment(self, k, v):
        self.segment_name = v

    def _parse_other(self, k, v):
        if k in self.rights:
            self.rights[k] = self._bool_dict[v]
        else:
            # XXX handle system rights, based on segment type of target segment
            # XXX How? we don't know the type of the target segment!
            print "unrecognized attribute", k

    def __init__(self, segment, ad_tree):
        d = { 'name': self._parse_name,
              'index': self._parse_index,
              'segment': self._parse_segment }

        self.segment = segment
        assert segment.base_type == 'access_segment'
        assert len(ad_tree) == 0
        super(AD, self).__init__(segment, ad_tree)
        self.size = 4
        self.segment_name = None
        self.dir_index = None
        self.seg_index = None
        self.rights = { 'write' : True,
                        'read'  : True,
                        'heap'  : False,
                        'delete': True,
                        'sys1'  : False,
                        'sys2'  : False,
                        'sys3'  : False }

        for k, v in ad_tree.attrib.iteritems():
            d.get(k, self._parse_other)(k, v)

        if not hasattr(self, 'valid'):
            self.valid = self.segment_name is not None

    def write_value(self):
        if self.valid:
            if self.segment_name not in self.image.descriptor_by_name:
                print "can't find segment", self.segment_name
            assert self.segment_name in self.image.descriptor_by_name
            descriptor = self.image.descriptor_by_name[self.segment_name]
            if self.dir_index is None:
                self.dir_index = descriptor.dir_index
                self.seg_index = descriptor.seg_index
            # XXX write value
            descriptor.reference_count += 1
            pass
        else:
            # XXX write zeros
            pass

class DataField(Field):
    def __init__(self, segment, field_tree):
        assert segment.base_type == 'data_segment'
        super(DataField, self).__init__(segment, field_tree)

    def write_value(self):
        pass # XXX

class ObjectTableEntry(Field):
    def __init__(self, segment):
        super(ObjectTableEntry, self).__init__(segment, None)
        self.size = 16

    def write_value(self):
        pass # XXX

class ObjectTableHeader(ObjectTableEntry):
    def __init__(self, segment):
        super(ObjectTableHeader, self).__init__(segment)
        self.offset = 0

class StorageDescriptor(ObjectTableEntry):
    def __init__(self, segment, descriptor, index):
        super(StorageDescriptor, self).__init__(segment)
        self.descriptor = descriptor
        self.offset = index * 16

class RefinementDescriptor(ObjectTableEntry):
    def __init__(self, segment, descriptor, index):
        super(RefinementDescriptor, self).__init__(segment)
        self.descriptor = descriptor
        self.offset = index * 16

class InterconnectDescriptor(ObjectTableEntry):
    def __init__(self, segment, descriptor, index):
        super(InterconnectDescriptor, self).__init__(segment)
        self.descriptor = descriptor
        self.offset = index * 16


# XXX change "Desciptor" to "Object"
class Descriptor(object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        d = { 'segment': Segment,
              'refinement': Refinement,
              'extended_type': ExtendedType }
        name = tree.get('name')
        assert name not in image.descriptor_by_name
        return d[tree.tag].parse(image, tree)

    def __init__(self, image, tree):
        self.name = tree.get('name')
        self.image = image
        self.arch = image.arch
        self.dir_index = None
        self.seg_index = None
        self.reference_count = 0

        self.object_table = tree.get('object_table')

        if 'dir_index' in tree.attrib:
            self._set_dir_index(int(tree.get('dir_index')))
        if 'seg_index' in tree.attrib:
            self._set_seg_index(int(tree.get('seg_index')))

    def _mark_coord(self):
        coord = (self.dir_index, self.seg_index)
        #print "descr", self.name, "assigned", coord
        assert coord not in self.image.descriptor_by_coord
        self.image.descriptor_by_coord[coord] = self
        seg_table = self.image.descriptor_by_coord[(2, self.dir_index)]
        seg_table.allocate_index(self, self.seg_index)
        

    def _set_dir_index(self, dir_index):
        if dir_index is None:
            return
        if self.dir_index is not None:
            assert dir_index == self.dir_index
        else:
            self.dir_index = dir_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                self._mark_coord()

    def _set_seg_index(self, seg_index):
        if seg_index is None:
            return
        if self.seg_index is not None:
            assert seg_index == self.seg_index
        else:
            self.seg_index = seg_index
            if (self.dir_index is not None and
                self.seg_index is not None):
                self._mark_coord()

    def assign_coordinates(self):
        if (self.dir_index is not None and
            self.seg_index is not None):
            if self.object_table:
                pass  # XXX verify that object table matches coordinates
            #print "already assigned dir_index", self.dir_index, "seg_index", self.seg_index
            return
        #print "assigning coordinates for", self.name
        if self.object_table:
            #print "looking up object table", self.object_table
            assert self.object_table in self.image.descriptor_by_name
            object_table = self.image.descriptor_by_name[self.object_table]
            dir_index = object_table.seg_index
            #if dir_index is None:
            #    print "recursively assigning coordinates"
            #    object_table.assign_coordinates()
            #    dir_index = object_table.seg_index
            #print "dir index", dir_index
            self._set_dir_index(dir_index)
        assert self.dir_index is not None
        if self.seg_index is None:
            #print "allocating a segment table entry"
            dir = self.image.descriptor_by_coord[(2, self.dir_index)]
            #print "dir", dir
            seg_index = dir.allocate_index() # finds an index but doesn't allocate
            self._set_seg_index(seg_index)   # actually allocates it
        #print "assigned dir_index", self.dir_index, "seg_index", self.seg_index


class Segment(Descriptor):
    # a factory method
    @staticmethod
    def parse(image, tree):
        d = { 'access_segment': AccessSegment,
              'data_segment' : DataSegment }
        name = tree.get('name')
        segment_type = tree.get('type')
        assert segment_type in image.arch.symbols
        st = image.arch.symbols[segment_type]
        return d[st.value.base_type].parse(image, tree)

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

        self.written = False

        self.fields = []
        for field_tree in segment_tree:
            self.fields.append(Field.parse(self, field_tree))

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
    # a factory method
    @staticmethod
    def parse(image, tree):
        return AccessSegment(image, tree)
    
    def __init__(self, image, segment_tree):
        super(AccessSegment, self).__init__(image, segment_tree)


class DataSegment(Segment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        segment_type = tree.get('type')
        assert segment_type in image.arch.symbols
        st = image.arch.symbols[segment_type]
        if st.value.system_type == 'object_table':
            return SegmentTable.parse(image, tree)
        else:
            return DataSegment(image, tree)

    def __init__(self, image, segment_tree):
        super(DataSegment, self).__init__(image, segment_tree)


class SegmentTable(DataSegment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        name = tree.get('name')
        if name == tree.get('object_table'):
            return SegmentTableDirectory(image, tree)
        else:
            return SegmentTable(image, tree)

    def __init__(self, image, segment_tree):
        super(SegmentTable, self).__init__(image, segment_tree)
        self._set_dir_index(2)
        self.index_allocation = Allocation(4096)

        self.allocate_index(0) # object table header
        object_table_header = ObjectTableHeader(self)
        self.fields.append(object_table_header)

    def allocate_index(self, descriptor=None, index=None):
        if index is None:
            return self.index_allocation.allocate(dry_run=True)
        else:
            # XXX following needs to handle other kinds of descriptors,
            #     based on object type
            object_table_entry = StorageDescriptor(self, descriptor, index)
            self.fields.append(object_table_entry)
            return self.index_allocation.allocate(pos=index, fixed=True)

class SegmentTableDirectory(SegmentTable):
    def __init__(self, image, segment_tree):
        assert image.segment_table_directory is None
        super(SegmentTableDirectory, self).__init__(image, segment_tree)
        self._set_seg_index(2)
        if self.phys_addr is None:
            self.phys_addr = 0  # address of segment prefix
        else:
            assert self.phys_addr == 0
        image.segment_table_directory = self

class InstructionSegment(Segment):
    # XXX not yet any way to instantiate this
    def __init__(self, image, segment_tree):
        super(InstructionSegment, self).__init__(image, segment_tree)
    


class Refinement(Descriptor):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return Refinement(image, tree)

    def __init__(self, image, descriptor_tree):
        super(Refinement, self).__init__(image, descriptor_tree)
        # XXX


class ExtendedType(Descriptor):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return ExtendedType(image, tree)

    def __init__(self, image, descriptor_tree):
        super(Refinement, self).__init__(image, descriptor_tree)
        # XXX


class Image(object):
    class InvalidDescriptorTypeError(Exception):
        def __init__(self, descriptor_tree):
            print descriptor_tree
            self.msg = 'invalid descriptor type "%s"' % descriptor_tree.tag

    def __init__(self, arch, image_tree):
        self.arch = arch
        image_root = image_tree.getroot()
        assert image_root.tag == 'image'
        self.descriptor_by_coord = { }
        self.descriptor_by_name = { }
        self.segment_table_directory = None

        for descriptor_tree in image_root:
            name = descriptor_tree.get('name')
            assert name not in self.descriptor_by_name
            self.descriptor_by_name[name] = Descriptor.parse(self, descriptor_tree)

        # compute sizes of all segments
        print "computing sizes of segments"
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, Segment):
                descriptor.compute_size()

        # assign coordinates to all segment tables
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        print "assigning coordinates of segment tables"
        for descriptor in self.descriptor_by_name.values():
            if isinstance(descriptor, SegmentTable):
                descriptor.assign_coordinates()

        # assign coordinates to all other descriptors
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        print "assigning coordinates of other descriptors"
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
    arg_parser.add_argument('--list-segments',
                            action='store_true')
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

    if args.list_segments:
        for k in sorted(image.descriptor_by_coord.keys()):
            d = image.descriptor_by_coord[k]
            print k, d.name

    for descriptor in image.descriptor_by_name.values():
        if descriptor.reference_count == 0:
            print "no AD references", descriptor.name
