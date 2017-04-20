#!/usr/bin/env python3
# Intel iAPX 432 image decoder

# Copyright 2016 Eric Smith <spacewar@gmail.com>

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
import attr
from bitarray import bitarray
import xml.etree.ElementTree
from collections import OrderedDict

from arch import Arch


class ObjectBuilderBase:
    def load_from_image(self, image, offset):
        for field in attr.fields(self.__class__):
            name = field.name
            lsb = field.metadata['lsb']
            width = field.metadata['width']
#            print('loading', name, lsb, width)
            field_bit_offset = 0
            image_byte_offset = offset + (lsb // 8)
            image_bit_offset = lsb % 8
            value = 0
            while width > 0:
                if image_bit_offset + width < 8:
                    bits_from_byte = width
                else:
                    bits_from_byte = 8 - image_bit_offset
#                print('image_byte_offset:', image_byte_offset,
#                      'image_bit_offset:', image_bit_offset)
                byte = image[image_byte_offset] >> image_bit_offset
                byte &= ((1 << bits_from_byte) - 1)
                value |= (byte << field_bit_offset)
                image_byte_offset += 1
                image_bit_offset = 0
                width -= bits_from_byte
                field_bit_offset += bits_from_byte
#            print('value:', value)
            setattr(self, name, value)
        return self



def object_builder_factory(class_name, *fields):
    c = attr.make_class(name = class_name,
                        attrs = { name : attr.ib(default = None,
                                                 metadata = { 'lsb'  : lsb,
                                                              'width': width })
                                  for (name, lsb, width) in fields },
                        bases = (ObjectBuilderBase,))
    return c


@attr.s(frozen = True)
class Coord:
    dir_index = attr.ib()
    seg_index = attr.ib()


AccessDescriptor = object_builder_factory('AccessDescriptor',
                                          ('dir_index',     20, 12),
                                          ('seg_index',      4, 12),
                                          ('valid',          0,  1),
                                          ('read',          18,  1),
                                          ('write',         19,  1),
                                          ('delete',        16,  1),
                                          ('heap',          17,  1),
                                          ('system_rights',  1,  3))


    

ObjectTableHeader = object_builder_factory('ObjectTableHeader',
                                           ('descriptor_type',    0,  5),
                                           ('preserved_5',        5,  11),
                                           ('reserved_16',        16, 4),
                                           ('free_index',         20, 12),
                                           ('reserved_32',        32, 4),
                                           ('end_index',          36, 12),
                                           ('fault_level_number', 48, 16),
                                           ('preserved_64',       64, 8),
                                           ('reclamation',        72, 1),
                                           ('level_number',       80, 16),
                                           ('storage_claim',      96, 32))

FreeDescriptor = object_builder_factory('FreeDescriptor',
                                        ('descriptor_type',    0,  5),
                                        ('preserved_5',        5,  11),
                                        ('reserved_16',        16, 4),
                                        ('free_index',         20, 12),
                                        ('preserved_32',       32, 32),
                                        ('preserved_64',       64, 8),
                                        ('reclamation',        72, 1),
                                        ('reserved_73',        73, 7),
                                        ('reserved_80',        80, 16),
                                        ('preserved_96',       96, 16))

StorageDescriptor = object_builder_factory('StorageDescriptor',
                                           ('descriptor_type',    0,  2),
                                           ('valid',              2,  1),
                                           ('base_type',          3,  1),
                                           ('storage_associated', 4,  1),
                                           ('io_lock',            5,  1),
                                           ('altered',            6,  1),
                                           ('accesed',            7,  1),
                                           ('segment_base',       8,  24),
                                           ('segment_length',     32, 16),
                                           ('preserved_48',       48, 16),
                                           ('system_type',        64, 5),
                                           ('processor_class',    69, 3),
                                           ('reclamation',        72, 1),
                                           ('reserved_73',        73, 7),
                                           ('level_number',       80, 16),
                                           ('dirty',              96, 1),
                                           ('preserved',          97, 31))

RefinementDescriptor = object_builder_factory('RefinementDescriptor',
                                              ('descriptor_type',    0,  2),
                                              ('valid',              2,  1),
                                              ('base_type',          3,  1),
                                              ('bypass_seg_index',   4, 12),
                                              ('preserved_16',      16,  4),
                                              ('bypass_dir_index',  20, 12),
                                              ('refinement_length', 32, 16),
                                              ('base_displacement', 48, 16),
                                              ('system_type',       64,  5),
                                              ('processor_class',   69,  3),
                                              ('reclamation',       72,  1),
                                              ('reserved_73',       73,  7),
                                              ('level_number',      80, 16),
                                              ('ad_preserved_96',   96,  4),
                                              ('ad_seg_index',     100, 12),
                                              ('ad_preserved_112', 112,  4),
                                              ('ad_dir_index',     116, 12))

TypeDescriptor = object_builder_factory('TypeDescriptor',
                                        ('descriptor_type',       0,  2),
                                        ('valid',                 2,  1),
                                        ('private',               3,  1),
                                        ('preserved_4',           4, 32),
                                        ('tdo_seg_index',        36, 12),
                                        ('preserved_48',         48,  4),
                                        ('tdo_dir_index',        52, 12),
                                        ('preserved_64',         64,  8),
                                        ('reclamation',          72,  1),
                                        ('reserved_73',          73,  7),
                                        ('level',                80, 16),
                                        ('preserved_96',         96,  4),
                                        ('typed_obj_seg_index', 100, 12),
                                        ('preserved_112',       112,  4),
                                        ('typed_obj_dir_index', 116, 12))

InterconnectDescriptor = object_builder_factory('InterconnectDescriptor',
                                                ('descriptor_type',    0,  2),
                                                ('valid',              2,  1),
                                                ('descriptor_subtype', 3,  2),
                                                ('io_lock',            5,  1),
                                                ('altered',            6,  1),
                                                ('accessed',           7,  1),
                                                ('base_address',       8,  24),
                                                ('length',             32, 16),
                                                ('preserved_48',       48, 16),
                                                ('preserved_64',       64, 8),
                                                ('reclamation',        72, 1),
                                                ('reserved_73',        73, 7),
                                                ('level',              80, 16),
                                                ('preserved_96',       96, 16))


def parse_descriptor(image, offset):
    v = image[offset]
    descriptor = None
    if v & 3 == 3:
        descriptor = StorageDescriptor()
    elif v & 3 == 2:
        descriptor = RefinementDescriptor()
    elif v & 3 == 1:
        descriptor = TypeDescriptor()
    elif v & 0x18 == 1:
        descriptor = InterconnectDescriptor()
    elif v & 0x18 == 0:
        if v & 4 == 0:
            descriptor = ObjectTableHeader()
        else:
            descriptor = FreeDescriptor()
    if descriptor is None:
        print('%06x: %02x' % (offset, v))
        assert descriptor is not None
    return descriptor.load_from_image(image, offset)


object_table = { }


class Segment:
    _image = None
    _segments = { }
    _mem_map = bitarray(1<<24)

    # Do not construct a Segment directly! Use the get_segment() method.
    def __init__(self, image, base, length, coord, guard = False):
        assert guard
        if Segment._image is None:
            assert image is not None
            Segment._image = image
        self.base = base
        self.length = length
        self.prefix = image[base-8:base]
        self.ad_image = AccessDescriptor().load_from_image(self.prefix, 0)
        assert self.ad_image.dir_index == coord.dir_index
        assert self.ad_image.seg_index == coord.seg_index
        l2 = length
        if l2 % 8 != 0:
            l2 += 8 - (l2 % 8)
        assert not Segment._mem_map[base-8:base+12].any()
        Segment._mem_map[base-8:base+l2] = True
        self.data = image[base:base+length]

    @classmethod
    def get_segment(cls, coord, image = None, base = None, length = None):
        global object_table
        if coord in Segment._segments:
            return Segment._segments[coord]
        if (coord.dir_index in object_table and
            coord.seg_index < len(object_table[coord.dir_index])):
            assert image is None and base is None and length is None
            descriptor = object_table[coord.dir_index][coord.seg_index]
            assert isinstance(descriptor, StorageDescriptor)
            Segment._segments[coord] = Segment(Segment._image,
                                               descriptor.segment_base,
                                               descriptor.segment_length,
                                               coord,
                                               guard = True)
        else:
            assert image is not None and base is not None and length is not None
            Segment._segments[coord] = Segment(image,
                                               base,
                                               length,
                                               coord,
                                               guard = True)
        return Segment._segments[coord]
    
    def get_base_addr(self):
        return self.base_addr

    def get_length(self):
        return self.length

    def get_ad_image(self):
        return self.ad_image

    def __getitem__(self, key):
        return self.data.__getitem__(key)


def parse_object_table(coord):
    ot_segment = Segment.get_segment(coord)
    offset = 0

    header = parse_descriptor(ot_segment, offset)
    assert isinstance(header, ObjectTableHeader)
    table = [header]
    #print('object table header', header)

    index = 1
    while (index * 16) < ot_segment.get_length():
        descriptor = parse_descriptor(ot_segment, index * 16)
        if coord == Coord(2, 2):
            assert (isinstance(descriptor, StorageDescriptor) or
                    isinstance(descriptor, FreeDescriptor))
        table.append(descriptor)
        index += 1
    return table

def parse_object_table_hierarchy(image):
    global object_table

    otd_descriptor = parse_descriptor(image, 8 + 32)
    assert isinstance(otd_descriptor, StorageDescriptor)
    otd_segment = Segment.get_segment(Coord(2, 2),
                                      image,
                                      otd_descriptor.segment_base,
                                      otd_descriptor.segment_length)
    object_table[2] = parse_object_table(Coord(2, 2))
    
    # validate that descriptor points to object table directory
    assert object_table[2][2].segment_base == 8

    for index in range(1, len(object_table[2])):
        if index == 2:
            continue
        ot_descriptor = object_table[2][index]
        if index > 2 and isinstance(ot_descriptor, FreeDescriptor):
            continue
        assert isinstance(ot_descriptor, StorageDescriptor)
        object_table[index] = parse_object_table(Coord(2, index))


def parse_image(image):
    parse_object_table_hierarchy(image)
#    offset = 0
#    while offset < len(image):
#        l = parse_segment(image, offset)
#        offset += l

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='iAPX 432 Image Decoder')
    arg_parser.add_argument('-a', '--arch',
                            type=argparse.FileType('r'),
                            default='iapx432-1.0.xml',
                            help='architecture definition (XML)')
    arg_parser.add_argument('image_binary',
                            type=argparse.FileType('rb'),
                            nargs=1,
                            help='image binary input')

    args = arg_parser.parse_args()

    arch_tree = xml.etree.ElementTree.parse(args.arch)
    args.arch.close()
    arch = Arch(arch_tree)

    image = args.image_binary[0].read()
    args.image_binary[0].close()

    parse_image(image)
