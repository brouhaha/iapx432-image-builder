#!/usr/bin/python2

# Copyright 2014, 2015 Eric Smith <spacewar@gmail.com>

import argparse
import pprint
import re
import sys
import xml.etree.ElementTree

from arch import Arch


class Allocation(object):
    # This could be eight times as storage-efficient, at a substantial
    # increase in complexity, by storing eight bits per byte instead
    # of only one.
    class AllocationError(Exception):
        pass
    
    def __init__(self, size, name = None):
        self.name = name
        self._v = bytearray(size)
        self._z = bytearray(size)  # in Python 3, this could be a bytes object

    def __str__(self):
        return ' '.join(["%d" % b for b in self._v])

    def allocate(self, size=1, pos=0, fixed=False, dry_run=False):
        #print "allocating from:", self.name, "size:", size, "pos:", pos, "fixed:", fixed, "dry_run:", dry_run
        if not fixed:
            pos = self._v.find(self._z[:size], pos)
            if pos < 0:
                raise self.AllocationError()
            if max is not None and pos + size > max:
                raise self.AllocationError()
        if self._v[pos:pos+size] != self._z[:size]:
            #print "pos:", pos, "size:", size
            #print [int(x) for x in self._v[pos:pos+size]]
            raise self.AllocationError()
        if not dry_run:
            self._v[pos:pos+size] = [1] * size
        #print "returning pos", pos
        return pos

    #def find_space(self, size=1, pos=0, fixed=False):
    #    return self.allocate(size=size, pos=pos, fixed=fixed, dry_run=True)

    def discontiguous(self):
        # XXX
        return False


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
        self.allocated = False
        self.size = None
        self.offset = None

    def allocate(self):
        if self.allocated:
            return
        assert self.size is not None
        if self.offset is None:
            self.offset = self.segment.allocation.allocate(size = self.size)
        else:
            self.segment.allocation.allocate(size = self.size,
                                                           pos = self.offset,
                                                           fixed = True)
            
        self.allocated = True

    def compute_size(self):
        if self.size is None:
            # XXX hack:
            self.size = 4
        return self.size

    def write_value(self):
        assert False

class AD(Field):
    _bool_dict = { 'true': True,
                     '1': True,
                     'false': False,
                     '0': False }

    def _parse_name(self, k, v):
        # XXX doesn't do anything yet, but eventually allow
        #     ad-hoc definition of a name for an AD slot in an object
        pass

    def _parse_index(self, k, v):
        try:
            offset = 4 * int(v, 0)
        except ValueError:
            s = self.arch.symbols[self.segment.segment_type]
            assert s.type == 'segment'
            assert v in s.value.field_by_name
            f = s.value.field_by_name[v]
            offset = f.offset
        if self.offset is not None:
            assert offset == self.offset
        else:
            self.offset = offset

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

        # XXX if AD is defined in arch to have a type, we
        # should verify it!

    def write_value(self):
        value = 0
        if self.valid:
            if self.segment_name not in self.image.object_by_name:
                print "can't find segment", self.segment_name
            assert self.segment_name in self.image.object_by_name
            obj = self.image.object_by_name[self.segment_name]
            if self.dir_index is None:
                self.dir_index = obj.dir_index
                self.seg_index = obj.seg_index
            obj.reference_count += 1

            value = ((self.dir_index        << 20) |
                     (self.rights['write']  << 19) |
                     (self.rights['read']   << 18) |
                     (self.rights['heap']   << 17) |
                     (self.rights['delete'] << 16) |
                     (self.seg_index        << 4) |
                     (self.rights['sys3']   << 3) |
                     (self.rights['sys2']   << 2) |
                     (self.rights['sys1']   << 1) |
                     1)  # valid

        self.segment.data[self.offset:self.offset + 4] = [(value >> (8*i)) & 0xff for i in range(4)]


class DataField(Field):
    def __init__(self, segment, field_tree):
        assert segment.base_type == 'data_segment'
        super(DataField, self).__init__(segment, field_tree)

    def write_value(self):
        pass # XXX

class ObjectTableEntry(Field):
    def __init__(self, segment, offset = None):
        super(ObjectTableEntry, self).__init__(segment, None)
        self.size = 16
        if offset is not None:
            self.offset = offset
            self.allocate()

    def write_value(self):
        pass # XXX

class ObjectTableHeader(ObjectTableEntry):
    def __init__(self, segment):
        super(ObjectTableHeader, self).__init__(segment, offset = 0)

    def set_free_index(self, index):
        pass

    # The end index is ony needed for stack OTs
    def set_end_index(self, index):
        pass

class FreeDescriptor(ObjectTableEntry):
    def __init__(self, segment, index):
        super(FreeDescriptor, self).__init__(segment)
        self.offset = index * 16

    def set_free_index(self, index):
        pass

class StorageDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super(StorageDescriptor, self).__init__(segment)
        self.obj = obj
        self.offset = index * 16

class RefinementDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super(RefinementDescriptor, self).__init__(segment)
        self.obj = obj
        self.offset = index * 16

class InterconnectDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super(InterconnectDescriptor, self).__init__(segment)
        self.obj = obj
        self.offset = index * 16


class Object(object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        d = { 'segment': Segment,
              'refinement': Refinement,
              'extended_type': ExtendedType }
        name = tree.get('name')
        assert name not in image.object_by_name
        return d[tree.tag].parse(image, tree)

    def __init__(self, image, tree):
        self.name = tree.get('name')
        self.image = image
        self.arch = image.arch
        self.dir_index = None
        self.seg_index = None
        self.reference_count = 0
        self.ote = None

        self.object_table = tree.get('object_table')

        if isinstance(self, SegmentTable) and self.object_table is None:
            self.object_table = image.segment_table_directory.name
            
        #print "name", self.name, "object table", self.object_table

        if 'dir_index' in tree.attrib:
            self._set_dir_index(int(tree.get('dir_index')))
            # XXX later need to verify that dir_index matches object table
        if 'seg_index' in tree.attrib:
            self._set_seg_index(int(tree.get('seg_index')))

    def _alloc_ote(self):
        if self.ote is None:
            if self.dir_index == 2 and self.seg_index == 2:
                seg_table = self
            else:
                seg_table = self.image.object_by_coord[(2, self.dir_index)]
            if self.seg_index is None:
                self.ote = ObjectTableEntry(seg_table)
                self.ote.allocate()
                self.seg_index = self.ote.offset / 16
            else:
                self.ote = ObjectTableEntry(seg_table, self.seg_index * 16)
                self.ote.allocate()
            self.image.object_by_coord[(self.dir_index, self.seg_index)] = self
            seg_table.fields.append(self.ote)
        else:
            if dir_index is not None:
                # assert ???
                pass
            if seg_index is not None:
                # assert ???
                pass

    def _mark_coord(self):
        #print "mark_coord for", self.name, "(%d, %d)" % (self.dir_index, self.seg_index)
        coord = (self.dir_index, self.seg_index)
        #print "descr", self.name, "assigned", coord
        assert coord not in self.image.object_by_coord
        self._alloc_ote()

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
            assert self.object_table in self.image.object_by_name
            object_table = self.image.object_by_name[self.object_table]
            dir_index = object_table.seg_index
            if dir_index is None:
                print "recursively assigning coordinates"
                object_table.assign_coordinates()
                dir_index = object_table.seg_index
            #print "dir index", dir_index
            self._set_dir_index(dir_index)
        assert self.dir_index is not None
        if self.seg_index is None:
            #print "allocating a segment table entry"
            self._alloc_ote()
            #object_table = self.image.object_by_name[self.object_table]
            #self.ote = ObjectTableEntry(object_table)
            #print "ote size", ote.size
            #self.ote.allocate()
            #object_table.fields.append(ote)
            #print "dir_index %d" % self.dir_index
            #print "ote offset %d" % ote.offset
            #self._set_seg_index(ote.offset / 16)
        #print "%s assigned dir_index %d seg_index %d" % (self.name, self.dir_index, self.seg_index)


# attributes:
#   name
#   type
#   object_table
#   dir_index
#   seg_index
#   reserve
# Must have either object_table or dir_index.
# XXX Maybe replace object_table with a numeric dir_index?
# contents:
#   ad (data_segment only)
#   field (access_segment only)
#   access_size
#   reserve_ad
class Segment(Object):
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

        self.data = bytearray(65536)
        self.allocation = Allocation(65536, self.name)

        self.written = False

        self.fields = []
        for field_tree in segment_tree:
            self.fields.append(Field.parse(self, field_tree))

    def abs_min_size(self):
        # don't allow a zero length data segment, round up to 1 byte
        # XXX note release 3 arch allows object to have zero-length data part,
        #     and/or zero-length access part
        return 1
    
    def compute_size(self):
        for field in self.fields:
            field.compute_size()
            # hack - we really need the sizes computed!
            if field.size is None:
                field.size = 4

        # first allocate fields at fixed offsets
        for field in self.fields:
            if (not field.allocated) and (field.offset is not None):
                try:
                    field.allocate()
                except Allocation.AllocationError as e:
                     print "segment %s field allocation error, pos %d, size %d" % (self.name, field.offset, field.size)

        # then allocate fields at dynamic offsets
        for field in self.fields:
            if not field.allocated:
                field.allocate()

        self.size = max(self.allocation.allocate(dry_run=True), self.min_size, self.abs_min_size())
        return self.size

    def write_to_image(self):
        if self.written:
            return
        self.written = True
        # allow 8 bytes for segment prefix, below the phys addr
        # and round up size to a multiple of 8
        rounded_size_with_prefix = 8 + ((self.size + 7) & ~7)
        #print "segment %s orig size %d rounded with prefix %d" % (self.name, self.size, rounded_size_with_prefix)
        if self.phys_addr is None:
            self.phys_addr = self.image.phys_mem_allocation.allocate(size = rounded_size_with_prefix) + 8
        else:
            # segment is at specified address
            self.image.phys_mem_allocation.allocate(size = rounded_size_with_prefix,
                                                    pos = self.phys_addr - 8,
                                                    fixed = True)
        #print "segment %s coord (%d, %d): phys addr %06x, size %d" % (self.name, self.dir_index, self.seg_index, self.phys_addr, self.size)
        # XXX write segment prefix at self.phys_addr - 8
        for field in self.fields:
            field.write_value()


class AccessSegment(Segment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return AccessSegment(image, tree)
    
    def __init__(self, image, segment_tree):
        super(AccessSegment, self).__init__(image, segment_tree)

    def abs_min_size(self):
        # don't allow a zero length access segment, round up to
        # one access descriptor
        return 4   
    

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

        self.min_free_descriptors = int(segment_tree.get('reserve', '0'))

        # segment table header
        self.object_table_header = ObjectTableHeader(self)
        self.fields.append(self.object_table_header)

    def write_to_image(self):
        if self.written:
            return

        # fill remaining space with free descriptors in a linked list
        prev_descriptor = self.object_table_header
        free_descriptor_count = 0
        index = 0
        while self.allocation.discontiguous() or free_descriptor_count < self.min_free_descriptors:
            index = self.allocation.allocate(size = 16) / 16
            free_descriptor = FreeDescriptor(self, index)
            self.fields.append(free_descriptor)
            prev_descriptor.set_free_index(index)
            free_descriptor_count += 1
            prev_descriptor = free_descriptor
        self.object_table_header.set_end_index(index)

        super(SegmentTable, self).write_to_image()

class SegmentTableDirectory(SegmentTable):
    def __init__(self, image, segment_tree):
        assert image.segment_table_directory is None
        image.segment_table_directory = self

        super(SegmentTableDirectory, self).__init__(image, segment_tree)

        self._set_seg_index(2)

        if self.phys_addr is None:
            self.phys_addr = 8  # segment prefix is at 0
        else:
            assert self.phys_addr == 8

class InstructionSegment(Segment):
    # XXX not yet any way to instantiate this
    def __init__(self, image, segment_tree):
        super(InstructionSegment, self).__init__(image, segment_tree)
    


class Refinement(Object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return Refinement(image, tree)

    def __init__(self, image, tree):
        super(Refinement, self).__init__(image, tree)
        # XXX


class ExtendedType(Object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return ExtendedType(image, tree)

    def __init__(self, image, tree):
        super(Refinement, self).__init__(image, tree)
        # XXX


class Image(object):
    class InvalidObjectTypeError(Exception):
        def __init__(self, tree):
            self.msg = 'invalid object type "%s"' % tree.tag

    def __init__(self, arch, image_tree):
        self.arch = arch
        image_root = image_tree.getroot()
        assert image_root.tag == 'image'
        self.object_by_coord = { }
        self.object_by_name = { }
        self.segment_table_directory = None
        self.phys_mem_allocation = Allocation(1 << 24, "phys mem")

        for obj_tree in image_root:
            name = obj_tree.get('name')
            assert name not in self.object_by_name
            self.object_by_name[name] = Object.parse(self, obj_tree)

        # assign coordinates to all segment tables
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        print "assigning coordinates of segment tables"
        for obj in self.object_by_name.values():
            if isinstance(obj, SegmentTable):
                obj.assign_coordinates()

        # assign coordinates to all other objects
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        print "assigning coordinates of other objects"
        for obj in self.object_by_name.values():
            obj.assign_coordinates()

        # compute sizes of all segments
        print "computing sizes of segments"
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                obj.compute_size()

        # if segment has a preassigned base address, write it
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                if obj.phys_addr is not None:
                    obj.write_to_image()

        # write all other segments
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                obj.write_to_image()


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
    arch = Arch(arch_tree)

    image_tree = xml.etree.ElementTree.parse(args.image[0])
    args.image[0].close()
    image = Image(arch, image_tree)

    print '%d segments in image' % len(image.object_by_name)

    if args.list_segments:
        for k in sorted(image.object_by_coord.keys()):
            d = image.object_by_coord[k]
            print "%06x" % d.phys_addr, k, d.name

    for obj in image.object_by_name.values():
        if obj.dir_index != 2 and obj.reference_count == 0:
            print "no AD references", obj.name

