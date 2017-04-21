#!/usr/bin/python3
# Intel iAPX 432 image builder

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

import argparse
import pprint
import re
import sys
import xml.etree.ElementTree

from arch import Arch
from allocation import Allocation

class Field(object):
    # a factory method
    @staticmethod
    def parse(segment, field_tree):
        d = { 'ad':    AD,
              'field': DataField,
              'code':  Code }
        return d[field_tree.tag](segment, field_tree)

    def __init__(self, segment, field_tree):
        self.segment = segment
        self.image = segment.image
        self.arch = self.image.arch
        # if field_tree is not None:
        #    self.name = field_tree.get('name')
        self.allocated = False
        self.size_bits = None     # in bits
        self.offset_bits = None   # in bits from start of segment
        self.non_byte = False
        self.skip = False

    def allocate(self):
        if self.allocated:
            return
        if self.size_bits == 0:
            return
        if self.skip:
            return # XXX
        if self.non_byte:
            return # XXX
        if self.size_bits is None:
            print("size of field at bit offset", self.offset_bits, "unknown")
            print(self)
        assert self.size_bits is not None
        if self.offset_bits is None:
            #print("segment", self.segment.name, "allocating size", self.size_bits, "bits")
            self.offset_bits = self.segment.allocation.allocate(size = self.size_bits)
        else:
            #print("segment", self.segment.name, "allocating size", self.size_bits, "bits at bit offset", self.offset_bits)
            self.segment.allocation.allocate(size = self.size_bits,
                                             pos = self.offset_bits,
                                             fixed = True)
        self.allocated = True

    def compute_size(self):
        if self.size_bits is None:
            # XXX hack:
            self.size_bits = 32
        return self.size_bits

    def write_value(self):
        assert self.size_bits == 0


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
            offset_bits = 32 * int(v, 0)
        except ValueError:
            s = self.arch.symbols[self.segment.segment_type]
            assert s.type == 'segment'
            assert v in s.value.field_by_name
            f = s.value.field_by_name[v]
            offset_bits = f.offset_bits
        if self.offset_bits is not None:
            assert offset_bits == self.offset_bits
        else:
            self.offset_bits = offset_bits

    def _parse_segment(self, k, v):
        self.segment_name = v

    def _parse_other(self, k, v):
        if k in self.rights:
            self.rights[k] = self._bool_dict[v]
        else:
            # XXX handle system rights, based on segment type of target segment
            # XXX How? we don't know the type of the target segment!
            print("unrecognized attribute", k)

    def __init__(self, segment, ad_tree):
        super().__init__(segment, ad_tree)
        assert segment.base_type == 1
        assert len(ad_tree) == 0  # no children
        d = { 'name': self._parse_name,
              'index': self._parse_index,
              'segment': self._parse_segment }
        self.size_bits = 32
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

        for k, v in ad_tree.attrib.items():
            d.get(k, self._parse_other)(k, v)

        if not hasattr(self, 'valid'):
            self.valid = self.segment_name is not None

        # XXX if AD is defined in arch to have a type, we
        # should verify it!

    def compute_size(self):
        self.size_bits = 32
        return self.size_bits

    def write_value(self):
        ad = 0
        if self.valid:
            if self.segment_name not in self.image.object_by_name:
                print("can't find segment", self.segment_name)
            assert self.segment_name in self.image.object_by_name
            obj = self.image.object_by_name[self.segment_name]
            if self.dir_index is None:
                self.dir_index = obj.dir_index
                self.seg_index = obj.seg_index
            obj.reference_count += 1

            ad = ((self.dir_index        << 20) |
                  (self.rights['write']  << 19) |
                  (self.rights['read']   << 18) |
                  (self.rights['heap']   << 17) |
                  (self.rights['delete'] << 16) |
                  (self.seg_index        << 4) |
                  (self.rights['sys3']   << 3) |
                  (self.rights['sys2']   << 2) |
                  (self.rights['sys1']   << 1) |
                  1)  # valid

        self.segment.write_u32_to_image(self.offset_bits, ad)


class DataField(Field):
    def _parse_name(self, k, v):
        # XXX doesn't do anything yet, but eventually allow
        #     ad-hoc definition of a name for a data field in an object
        self.name = v

    def _parse_value(self, k, v):
        try:
            self.value = int(v, 0)
        except ValueError:
            self.value = v

    def _parse_type(self, k, v):
        self.type = v
        
    def _parse_other(self, k, v):
        print("unrecognized atribute", k)
        
    def __init__(self, segment, field_tree):
        super().__init__(segment, field_tree)
        assert segment.base_type == 0
        self.name = None
        self.value = None
        self.type = None
        self.numeric = False
        d = { 'name':  self._parse_name,
              'value': self._parse_value,
              'type':  self._parse_type}
        for k, v in field_tree.attrib.items():
            d.get(k, self._parse_other)(k, v)

        assert self.name is not None

        if self.type is None:
            s = self.arch.symbols[self.segment.segment_type]
            assert s.type == 'segment'
            if self.name not in s.value.field_by_name:
                print("field name:", self.name)
                print("known fields:", s.value.field_by_name)
            assert self.name in s.value.field_by_name
            f = s.value.field_by_name[self.name]

            if f.offset_bits is None or f.size_bits is None:
                self.skip = True
                return

            if (f.offset_bits % 8 != 0) or (f.size_bits % 8 != 0):
                # XXX non-byte-boundary field, can't yet handle
                #print("offset of field in bits", self.name, "is", f.offset_bits)
                #print("size of field in bits", self.name, "is", f.size_bits)
                self.non_byte = True
                self.skip = True
                return

            self.type = f.type
            self.offset_bits = f.offset_bits
            self.size_bits = f.size_bits
            if self.type == 'ordinal':
                self.numeric = True
        else:
            if self.type == 'character':
                self.size_bits = 8
                self.numeric = True
            elif self.type == 'short_ordinal':
                self.size_bits = 16
                self.numeric = True
            elif self.type == 'ordinal':
                self.size_bits = 32
                self.numeric = True
            elif self.type == 'object_selector':
                self.size_bits = 16
            
        if not self.numeric:
            self.skip = True
            return
        
        assert self.value is not None


    def write_value(self):
        if self.non_byte:
            return # XXX
        if self.skip:
            return # XXX
        if not self.numeric:
            return # XXX
        bytes = [(self.value >> (8*i)) & 0xff for i in range(self.size_bits//8)]
        self.segment.write_byte_to_image(self.offset_bits, bytes)


class CodeItem(object):
    @staticmethod
    def parse(field, item_tree):
        d = { 'label':       Label,
              'assume':      Assume, 
              'instruction': Instruction }
        return d[item_tree.tag](field, item_tree)

class Label(CodeItem):
    def _parse_name(self, k, v):
        self.name = v

    def _parse_other(self, k, v):
        print("unrecognized label attribute", k)

    def __init__(self, field, item_tree):
        self.name = None
        d = { 'name': self._parse_name }
        for k, v in item_tree.attrib.items():
            d.get(k, Label._parse_other)(k, v)
        assert self.name is not None
        assert self.name not in field.segment.labels
        field.segment.labels[self.name] = field.segment.ip

class Assume(CodeItem):
    def __init__(self, field, item_tree):
        self.eas_index = int(item_tree.get('eas'))
        assert 0 <= self.eas_index <= 3
        self.seg_name = item_tree.get('segment')
        field.segment.eas[self.eas_index] = self.seg_name

class Instruction(CodeItem):
    def __init__(self, field, item_tree):
        pass


class Code(Field):
    def __init__(self, segment, field_tree):
        super().__init__(segment, field_tree)
        assert segment.base_type == 0
        assert segment.__class__ == InstructionSegment
        self.size_bits = 0 # each instruction will be allocated as it is parsed
        self.items = []
        d = { 'label':       Label,
              'assume':      Assume, 
              'instruction': Instruction }
        for item in field_tree:
            self.items.append(CodeItem.parse(self, item))

class ObjectTableEntry(Field):
    def __init__(self, segment, offset_bits = None):
        #print("creating OTE, offset", offset)
        super().__init__(segment, None)
        self.size_bits = 128
        self.descriptor = [0, 0, 0, 0]
        if offset_bits is not None:
            #print("known offset, allocating")
            self.offset_bits = offset_bits
            self.allocate()

    def write_value(self):
        for i in range(len(self.descriptor)):
            self.segment.write_u32_to_image(self.offset_bits, self.descriptor)

class ObjectTableHeader(ObjectTableEntry):
    def __init__(self, segment):
        #print("Creating ObjectTableHeader")
        super().__init__(segment, offset_bits = 0)
        self.free_index = 0
        self.end_index = 0

    def set_free_index(self, index):
        self.free_index = index

    # For Rel. 3 arch, the end index is only needed for stack OTs.
    def set_end_index(self, index):
        self.end_index = index

    def write_value(self):
        self.descriptor[0] = ((0x00 << 0) |              # free descriptor
                              (self.free_index << 20))
        self.descriptor[1] = ((self.end_index << 4) |
                              (0 << 16))                 # fault level number
        self.descriptor[2] = ((0 << 8) |                 # reclamation
                              (0 << 16))                 # XXX level number
        self.descriptor[3] = (0xffffffff)                # infinite
        super().write_value()

class FreeDescriptor(ObjectTableEntry):
    def __init__(self, segment):
        super().__init__(segment)
        self.free_index = 0

    def set_free_index(self, index):
        self.free_index = index

    def write_value(self):
        self.descriptor[0] = (0x04 | # free descriptor
                              (self.free_index << 20))
        super().write_value()

class StorageDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super().__init__(segment)
        self.obj = obj
        self.offset_bits = index * 128
        self.level_number = 0 # XXX global

    def write_value(self):
        self.descriptor[0] = ((0x03 << 0) |                       # storage descriptor
                              (1 << 2) |                          # valid
                              (self.obj.base_type << 3) |         # base type
                              (True << 4) |                       # storage associated
                              (0   << 5) |                        # input/output lock
                              (0   << 6) |                        # altered
                              (0   << 7) |                        # accessed
                              (self.obj.phys_addr << 8))
        self.descriptor[1] = (self.obj.size_bits // 8) - 1
        self.descriptor[2] = ((self.obj.system_type << 0) |       # system type
                              (self.obj.processor_class << 5) |   # processor class
                              (0   << 8) |                        # reclamation
                              (self.obj.level_number << 16))      # level number
        self.descriptor[3] = ((0 << 0))                           # dirty bit
        super().write_value()

class RefinementDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super().__init__(segment)
        self.obj = obj
        self.offset_bits = index * 16

class InterconnectDescriptor(ObjectTableEntry):
    def __init__(self, segment, obj, index):
        super().__init__(segment)
        self.obj = obj
        self.offset_bits = index * 16


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
        self.level_number = 0  # XXX global
        self.reference_count = 0
        self.ote = None

        self.object_table = tree.get('object_table')

        if isinstance(self, SegmentTable) and self.object_table is None:
            self.object_table = image.segment_table_directory.name
            
        #print("name", self.name, "object table", self.object_table)

        if 'dir_index' in tree.attrib:
            self._set_dir_index(int(tree.get('dir_index')))
            # XXX later need to verify that dir_index matches object table
        if 'seg_index' in tree.attrib:
            self._set_seg_index(int(tree.get('seg_index')))

    def create_object_descriptor(self, seg_table):
        assert 0   # abstract

    def _alloc_ote(self):
        if self.ote is None:
            #print("allocating ote for segment", self.name)
            if self.dir_index == 2 and self.seg_index == 2:
                seg_table = self
            else:
                seg_table = self.image.object_by_coord[(2, self.dir_index)]
            if self.seg_index is None:
                self.seg_index = seg_table.allocation.allocate(size=128,
                                                               dry_run=True) // 128
            self.ote = self.create_object_descriptor(seg_table)
            self.ote.allocate()
            assert self.seg_index == self.ote.offset_bits // 128
            self.image.object_by_coord[(self.dir_index, self.seg_index)] = self
            seg_table.fields.append(self.ote)
        else:
            if self.dir_index is not None:
                # assert ???
                pass
            if self.seg_index is not None:
                # assert ???
                pass

    def _mark_coord(self):
        #print("mark_coord for", self.name, "(%d, %d)" % (self.dir_index, self.seg_index))
        coord = (self.dir_index, self.seg_index)
        #print("descr", self.name, "assigned", coord)
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
            
            # XXX verify that object table matches coordinates
            #print("segment %s coordinates already assigned: (%d, %d)" % (self.name, self.dir_index, self.seg_index))
            return
        #print("assigning coordinates for", self.name)
        if self.object_table:
            #print("looking up object table", self.object_table)
            assert self.object_table in self.image.object_by_name
            object_table = self.image.object_by_name[self.object_table]
            dir_index = object_table.seg_index
            if dir_index is None:
                print("recursively assigning coordinates")
                object_table.assign_coordinates()
                dir_index = object_table.seg_index
            #print("dir index", dir_index)
            self._set_dir_index(dir_index)
        assert self.dir_index is not None
        if self.seg_index is None:
            #print("allocating a segment table entry")
            self._alloc_ote()
            #object_table = self.image.object_by_name[self.object_table]
            #self.ote = ObjectTableEntry(object_table)
            #print("ote size", ote.size)
            #self.ote.allocate()
            #object_table.fields.append(ote)
            #print("dir_index %d" % self.dir_index)
            #print("ote offset %d" % ote.offset_bits)
            #self._set_seg_index(ote.offset_bits // 16)
        #print("%s assigned dir_index %d seg_index %d" % (self.name, self.dir_index, self.seg_index))


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
        d = { 1: AccessSegment,
              0: DataSegment }
        name = tree.get('name')
        segment_type = tree.get('type')
        assert segment_type in image.arch.symbols
        st = image.arch.symbols[segment_type]
        assert st.type == 'segment'
        return d[st.value.base_type].parse(image, tree)

    def __init__(self, image, segment_tree):
        super().__init__(image, segment_tree)
        self.segment_type = segment_tree.get('type')
        assert self.segment_type in self.arch.symbols
        st = self.arch.symbols[self.segment_type]
        assert st.type == 'segment'
        self.system_type = st.value.system_type
        self.base_type = st.value.base_type
        self.processor_class = st.value.processor_class

        self.phys_allocated = False
        self.phys_addr = None
        self.size_bits = None

        self.min_size_bits = segment_tree.get('min_size')
        if self.min_size_bits is None:
            self.min_size_bits = 0
        #self.phys_addr = segment_tree.get('phys_addr')  # address of segment prefix

        self.allocation = Allocation(65536*8, self.name)

        self.written = False

        self.fields = []
        for field_tree in segment_tree:
            self.fields.append(Field.parse(self, field_tree))
        # XXX for system segments, need to include the fields that are
        #     defined for the system segment, but may not be present in
        #     the image definition.
        #print("segment %s type" % self.name, self.segment_type)
        #print("st", st.value)
        for arch_field in st.value.fields:
            if not hasattr(arch_field, 'size_bits'):
                print(type(arch_field))
                print(dir(arch_field))
                print('name', arch_field.name)
                print('size', arch_field.size)
                print('offset', arch_field.offset)
            if arch_field.size_bits is None:
                #print("arch field %s offset %d size unk." % (arch_field.name, arch_field.offset_bits))
                pass
            elif arch_field.offset_bits is None:
                #print("arch field %s offset unk." % (arch_field.name))
                pass
            else:   
                #print("arch field %s offset %d size %d" % (arch_field.name, arch_field.offset_bits, arch_field.size_bits))
                pass

    def abs_min_size_bits(self):
        # don't allow a zero length data segment, round up to 1 byte
        # XXX note release 3 arch allows object to have zero-length data part,
        #     and/or zero-length access part
        return 8
    
    def compute_size(self):
        # first allocate fields at fixed offsets
        for field in self.fields:
            if (not field.allocated) and (field.offset_bits is not None):
                try:
                    field.allocate()
                except Allocation.AllocationError as e:
                     print("segment %s field allocation error, pos %d, size %d" % (self.name, field.offset_bits, field.size_bits))

        # then allocate fields at dynamic offsets
        for field in self.fields:
            if not field.allocated:
                field.allocate()

        try:
            self.size_bits = max(self.allocation.highest_allocated() + 1,
                                 self.min_size_bits,
                                 self.abs_min_size_bits())
        except Exception as e:
            print(e)
            print(self.allocation.highest_allocated(),
                  self.min_size_bits,
                  self.abs_min_size_bits())
        return self.size_bits

    def allocate_physical_memory(self):
        if self.phys_allocated:
            return
        assert self.size_bits is not None
        # allow 8 bytes for segment prefix, below the phys addr
        # and round up size to a multiple of 8
        rounded_size_with_prefix = 64 + self.size_bits
        if rounded_size_with_prefix % 64 != 0:
            rounded_size_with_prefix += 64 - (rounded_size_with_prefix % 64)
        #print("segment %s orig size %d rounded with prefix %d" % (self.name, self.size_bits, rounded_size_with_prefix))
        if self.phys_addr is None:
            self.phys_addr = self.image.phys_mem_allocation.allocate(size = rounded_size_with_prefix // 8)
        else:
            # segment is at specified address
            self.image.phys_mem_allocation.allocate(size = rounded_size_with_prefix // 8,
                                                    pos = self.phys_addr - 8,
                                                    fixed = True)
        #print("segment %s coord (%d, %d): phys addr %06x, size %d" % (self.name, self.dir_index, self.seg_index, self.phys_addr, self.size_bits))
        self.phys_allocated = True


    def create_object_descriptor(self, seg_table):
        return StorageDescriptor(seg_table, self, self.seg_index)

    # can write a single byte or a sequence of bytes
    def write_byte_to_image(self, bit_offset, data):
        assert self.phys_addr is not None
        assert bit_offset % 8 == 0
        byte_offset = bit_offset // 8
        #print('bit offset %d, byte offset %d' % (bit_offset, byte_offset))
        pa = self.phys_addr + byte_offset
        if isinstance(data, int):
            #print('writing byte %02x to byte offset %04x, pa %06x' % (data, byte_offset, pa))
            self.image.phys_mem[pa] = data
        else:
            if byte_offset + len(data) > (self.size_bits * 8):
                print("byte offset %d, size bits %d, byte count %d" % (byte_offset, self.size_bits, len(data)))
            assert byte_offset + len(data) <= (self.size_bits * 8)
            #print('writing bytes %s to byte offset %04x, pa %06x' % (' '.join(['%02x' % d for d in data]), byte_offset, pa))
            self.image.phys_mem[pa:pa + len(data)] = data

    # can write a single u32 or a sequence of u32
    def write_u32_to_image(self, bit_offset, data):
        if isinstance(data, int):
            self.write_byte_to_image(bit_offset,
                                     [(data >> (8*j)) & 0xff for j in range(4)])
        else:
            for i in range(len(data)):
                self.write_u32_to_image(bit_offset + 32*i, data[i])

    def write_to_image(self):
        if self.written:
            return
        self.written = True
        #print('writing segment "%s" (%d,%d) at address %06x' % (self.name, self.dir_index, self.seg_index, self.phys_addr))

        # AD image in segment prefix doesn't need any rights bits set
        ad_image = ((self.dir_index        << 20) |
                    (self.seg_index        << 4) |
                    1)  # valid
        #print('AD image %08x' % (ad_image))
        
        # write segment prefix at self.phys_addr - 8
        self.write_u32_to_image(-64, ad_image)
        self.write_u32_to_image(-32, 0)

        for field in self.fields:
            field.write_value()


class AccessSegment(Segment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return AccessSegment(image, tree)
    
    def __init__(self, image, segment_tree):
        super().__init__(image, segment_tree)

    def abs_min_size(self):
        # don't allow a zero length access segment, round up to
        # one access descriptor
        return 4   
    

class DataSegment(Segment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        d = { 2: SegmentTable,
              3: InstructionSegment }
        segment_type = tree.get('type')
        assert segment_type in image.arch.symbols
        st = image.arch.symbols[segment_type].value.system_type
        if st in d:
            return d[st].parse(image, tree)
        else:
            return DataSegment(image, tree)

    def __init__(self, image, segment_tree):
        super().__init__(image, segment_tree)


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
        super().__init__(image, segment_tree)
        assert len(segment_tree) == 0   # can't have any data fields
        assert self.dir_index is None or self.dir_index is 2
        self._set_dir_index(2)

        self.min_free_descriptors = int(segment_tree.get('reserve', '0'))

        # segment table header
        self.object_table_header = ObjectTableHeader(self)
        self.fields.append(self.object_table_header)

    def compute_size(self):
        # fill remaining space with free descriptors in a linked list
        prev_descriptor = self.object_table_header
        free_descriptor_count = 0
        index = 0
        while self.allocation.discontiguous() or free_descriptor_count < self.min_free_descriptors:
            free_descriptor = FreeDescriptor(self)
            free_descriptor.allocate()
            index = free_descriptor.offset_bits // 128
            self.fields.append(free_descriptor)
            prev_descriptor.set_free_index(index)
            free_descriptor_count += 1
            prev_descriptor = free_descriptor
        self.object_table_header.set_end_index(index)
        return super().compute_size()

class SegmentTableDirectory(SegmentTable):
    def __init__(self, image, segment_tree):
        assert image.segment_table_directory is None
        image.segment_table_directory = self

        super().__init__(image, segment_tree)

        self._set_seg_index(2)

        if self.phys_addr is None:
            self.phys_addr = 8  # segment prefix is at 0
        else:
            assert self.phys_addr == 8

class InstructionSegment(DataSegment):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return InstructionSegment(image, tree)

    def __init__(self, image, segment_tree):
        self.labels = { }
        self.eas = [ None, None, None, None ]
        self.ip = 112  # XXX should get from definitions
        super().__init__(image, segment_tree)


class Refinement(Object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return Refinement(image, tree)

    def __init__(self, image, tree):
        super().__init__(image, tree)
        # XXX

    def create_object_descriptor(self, seg_table):
        return RefinementDescriptor(seg_table, self, self.seg_index)


class ExtendedType(Object):
    # a factory method
    @staticmethod
    def parse(image, tree):
        return ExtendedType(image, tree)

    def __init__(self, image, tree):
        super().__init__(image, tree)
        # XXX

    def create_object_descriptor(self, seg_table):
        assert 0  # XXX

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
        self.phys_mem = bytearray(1 << 24)

        for obj_tree in image_root:
            name = obj_tree.get('name')
            assert name not in self.object_by_name
            #print('Image.__init__() calling Object.parse() for %s' % name)
            self.object_by_name[name] = Object.parse(self, obj_tree)

    def assign_coordinates(self):
        # assign coordinates to all segment tables
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        for obj in self.object_by_name.values():
            if isinstance(obj, SegmentTable):
                obj.assign_coordinates()

        # assign coordinates to all other objects
        # XXX would be nice to process in order they're declared,
        #     which would require adding a list
        for obj in self.object_by_name.values():
            obj.assign_coordinates()

    def compute_segment_sizes(self):
        # compute sizes of all segments
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                obj.compute_size()

    def allocate_physical_memory(self):
        # allocate physical memory to objects at fixed addresses
        for obj in self.object_by_name.values():
            if obj.phys_addr is not None:
                obj.allocate_physical_memory()

        # allocate physical memory to all other objects
        for obj in self.object_by_name.values():
            obj.allocate_physical_memory()

    def write_segments(self):
        # if segment has a preassigned base address, write it
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                if obj.phys_addr is not None:
                    obj.write_to_image()

        # write all other segments
        for obj in self.object_by_name.values():
            if isinstance(obj, Segment):
                obj.write_to_image()

    def get_size(self):
        self.size = self.phys_mem_allocation.highest_allocated() + 1
        return self.size

    def write_to_file(self, f):
        f.write(self.phys_mem[0:self.size])
    

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='iAPX 432 Image Builder')
    arg_parser.add_argument('-a', '--arch',
                            type=argparse.FileType('r'),
                            default='iapx432-1.0.xml',
                            help='architecture definition (XML)')
    arg_parser.add_argument('--list-segments',
                            action='store_true')
    arg_parser.add_argument('image_definition',
                            type=argparse.FileType('r'),
                            nargs=1,
                            help='image definition (XML)')
    arg_parser.add_argument('image_binary',
                            type=argparse.FileType('wb'),
                            nargs=1,
                            help='image binary output')

    args = arg_parser.parse_args()

    arch_tree = xml.etree.ElementTree.parse(args.arch)
    args.arch.close()
    arch = Arch(arch_tree)

    image_tree = xml.etree.ElementTree.parse(args.image_definition[0])
    args.image_definition[0].close()
    image = Image(arch, image_tree)

    print("assigning coordinates of objects")
    image.assign_coordinates()

    # XXX need a pass after assigning coordinates parse contents of data
    # segments, so that intersegment references can be resolved

    print("computing sizes of segments")
    image.compute_segment_sizes()

    print("allocating physical memory to objects")
    image.allocate_physical_memory()
    
    print("writing segments to image")
    image.write_segments()

    image_size = image.get_size()
    print("image size %d (0x%06x)" % (image_size, image_size))

    print("writing image to output file")
    image.write_to_file(args.image_binary[0])
    

    print('%d objects in image' % len(image.object_by_coord))

    if args.list_segments:
        for k in sorted(image.object_by_coord.keys()):
            d = image.object_by_coord[k]
            print("%06x..%06x" % (d.phys_addr, d.phys_addr + d.size_bits // 8 - 1), k, d.name)

    for obj in image.object_by_name.values():
        if obj.dir_index != 2 and obj.reference_count == 0:
            print("no AD references", obj.name)

