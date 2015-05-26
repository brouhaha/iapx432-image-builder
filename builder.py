#!/usr/bin/python2

# Copyright 2014, 2015 Eric Smith <spacewar@gmail.com>

import argparse
import collections
import pprint
import re
import sys
import xml.etree.ElementTree

from arch import arch


def parse_segment(arch, segment):
    segment_name = segment.get('name')
    segment_type = segment.get('type')
    assert arch.symbols[segment_type][0] == 'segment'
    dir_index = segment.get('dir_index')
    seg_index = segment.get('seg_index')
    si = { 'name': segment_name,
           'type': segment_type,
           'dir_index': None,  # assume coordinates to be assigned
           'seg_index': None }
    # XXX if specified, get segment's coordinates (directory index and segment index)
    si['base_type'] = arch.symbols[si['type']][1]['base_type']
    si['system_type'] = arch.symbols[si['type']][1]['system_type']
    si['phys_addr'] = segment.get('phys_addr')
    assert si['base_type'] in arch.segment_base_type_names
    if si['base_type'] == 'data_segment':
        if si['system_type'] == 'object_table_data_segment':
            # XXX more code needed here
            # assert dir_index not present or equal to 2
            # assert seg_index not present, or greater than 0 and not equal to 2
            # XXX check for reserve="n"
            # check that no children
            pass
        else:
            si['fields'] = []
            offset = 0
            for field in segment:
                assert field.tag == 'field'
                f = { }
                f['type'] = field.get('type')
                # XXX lookup type to get size
                size = 8
                si['fields'].append(f)
                offset += size
    else: # 'access_segment'
        si['ad_slots'] = []
        offset = 0
        for ad_slot in segment:
            assert ad_slot.tag == 'ad_slot'
            ads = { }
            # XXX check whether name or index attribute, to get index
            # XXX index * 4 = offset
            ads['name'] = ad_slot.get('value')
            si['ad_slots'].append(ads)
            offset += 4
    si['size'] = offset  # does not include segment prefix
    return si

def process_image(arch, image_tree):
    segments = { }
    image_root = image_tree.getroot()

    assert image_root.tag == 'image'

    for segment in image_root:
        assert segment.tag == 'segment'
        segment_name = segment.get('name')
        segments[segment_name] = parse_segment(arch, segment)

    # XXX build object table directory

    for s in segments:
        # compute size of segment
        pass

    for s in segments:
        # if segment has a base address, construct at that address and mark
        # as written
        pass

    for s in segments:
        # if segment not written, assign a base address and write
        pass

    return segments


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='iAPX 432 Image Builder')
    parser.add_argument('-a', '--arch',
                        type=argparse.FileType('r', 0),
                        default='definitions.xml',
                        help='architecture definition (XML)')
    parser.add_argument('image',
                        type=argparse.FileType('r', 0),
                        nargs=1,
                        help='image definition (XML)')

    args = parser.parse_args()

    arch_tree = xml.etree.ElementTree.parse(args.arch)
    args.arch.close()
    arch = arch(arch_tree)

    image_tree = xml.etree.ElementTree.parse(args.image[0])
    args.image[0].close()
    segments = process_image(arch, image_tree)

    print '%d segments in image' % len(segments)

