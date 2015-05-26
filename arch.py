#!/usr/bin/python2

# Copyright 2014, 2015 Eric Smith <spacewar@gmail.com>

import argparse
import collections
import re
import sys
import xml.etree.ElementTree

class arch(object):
    symbol_t = collections.namedtuple('symbol_t', ['type',
                                                   'value'])

    segment_t = collections.namedtuple('segment_t', ['base_type',
                                                     'system_type'])

    size_value_t = collections.namedtuple('size_value_t', ['size',
                                                           'value'])
    size_value_t.__str__ = lambda(self): ("{:0" + str(self.size) + "b}").format(self.value)

    format_t = collections.namedtuple('format_t', ['encoding',
                                                   'operands'])

    class_t = collections.namedtuple('class_t', ['encoding',
                                                 'reserved',
                                                 'refs',
                                                 'branch_ref',
                                                 'operators'])

    operator_t = collections.namedtuple('operator_t', ['names',
                                                       'id',
                                                       'clas',
                                                       'encoding']) # opcode

    def get_single_element(self, base, element_name):
        el = base.findall(element_name)
        assert len(el) == 1
        return el[0]

    def get_single_named_element(self, base, element_name, attr_val, attr_name='name'):
        el = []
        for e in base.findall(element_name):
            if e.get(attr_name) == attr_val:
                el.append(e)
        assert len(el) == 1
        return el[0]

    def get_elements_dict(self, base, element_names, index_attr='name', exclusive=True):
        d = {}
        if type(element_names) is str:
            element_names = set([element_names])
        #for e in base.findall(element_name):
        for e in base:
            if exclusive:
                if e.tag not in element_names:
                    print 'tag', e.tag, 'element names', element_names
                    print e
                    sys.stdout.flush()
                assert e.tag in element_names
            else:
                if e.tag not in element_names:
                    continue
            if len(element_names) > 1:
                d[e.get(index_attr)] = (e.tag, e.attrib)
            else:
                d[e.get(index_attr)] = e.attrib
        return d

    def size_and_value(self, s, sz=0):
        if len(s) == 0:
            v = 0
        else:
            v = int(s, 0)
        if (s.startswith(('0b', '0B'))):
            sz2 = len(s) - 2
        elif (s.startswith(('0o', '0O'))):
            sz2 = 3 * (len(s) - 2)
        elif (s.startswith(('0x', '0X'))):
            sz2 = 4 * (len(s) - 2)
        elif (s.startswith('0')):
            sz2 = 3 * (len(s) - 1)
        else:
            sz2 = v.bit_length()
        if sz != 0:
            assert sz2 <= sz
        else:
            sz = sz2
        return self.size_value_t(sz, v)

    def is_prefix_of(self, v1, v2):
        return ((v1.size <= v2.size) and
                (v1.value == v2.value & ((1 << v1.size) - 1)))

    def max_encoding_len(self, d, attr='encoding'):
        max_len = 0
        for v in d.values():
            max_len = max(max_len, getattr(v, attr).size)
        return max_len

    # does not check for missing entries, use validate_encodings()
    def expand_encoding_dict(self, d, attr='encoding', force_bits=None):
        # items = d.values()
        # if len(items) == 0:
        #     return [ ]
        if force_bits is not None:
            max_len = force_bits
        else:
            max_len = self.max_encoding_len(d, attr=attr)
        if max_len == 0:
            return [ ]
        bin_entries = [ None ] * (1 << max_len)
        # for i in range(len(items)):
        for v in d.values():
            # enc_i = getattr(items[i], attr)
            enc_i = getattr(v, attr)
            for j in range(enc_i.value, 1 << max_len, 1 << enc_i.size):
                assert bin_entries [j] is None
                # bin_entries [j] = items [i]
                bin_entries [j] = v
        return bin_entries
    
    def is_enumeration_element(self, enum_name, enum_item_name):
        if enum_name not in self.symbols:
            return False
        et = self.symbols[enum_name]
        if et.type != 'enumeration':
            return False
        return enum_item_name in et.value
        

    def get_enumeration_value(self, enum_name, enum_item_name):
        assert enum_name in self.symbols
        et = self.symbols[enum_name]
        assert et.type == 'enumeration'
        assert enum_item_name in et.value
        return et.value[enum_item_name]

    def parse_enumeration(self, ee):
        size = ee.get('size')
        if size == 'var':
            size = 0
        else:
            size = int(size)
        ed = self.get_elements_dict(ee, 'constant')
        for e in ed:
            (es, v) = self.size_and_value(ed[e]['encoding'], size)
            ed[e]['value'] = v
            ed[e]['size'] = es
        return ed

    # also gets unions
    def get_struct(self, ee):
        size = ee.get('size')
        if size == 'var':
            size = 0
        else:
            size = int(size)
        # XXX could also be a struct or union
        ed = self.get_elements_dict(ee, set(('field','array')))
        return ed


    # ensure that no two entries in a dictionary have sized values that conflict
    # (neither can be a prefix of the other)
    # XXX would be nice to report missing encodings
    def validate_encodings (self, d, name, attr='encoding', check_missing=True):
        items = d.values()
        if len(items) == 0:
            return
        max_len = 0
        for i in range(len(items)-1):
            max_len = max(max_len, getattr(items[i], attr).size)
        for i in range(len(items)-1):
            enc_i = getattr(items[i], attr)
            for j in range(i+1, len(items)):
                enc_j = getattr(items[j], attr)
                if self.is_prefix_of(enc_i, enc_j):
                    print name, enc_i, 'is prefix of', enc_j
                if self.is_prefix_of(enc_j, enc_i):
                    print name, enc_j, 'is prefix of', enc_i
                assert ((not self.is_prefix_of(enc_i, enc_j)) and
                        (not self.is_prefix_of(enc_j, enc_i)))

        if not check_missing:
            return
        bin_entries = self.expand_encoding_dict(d)
        # for i in range(1 << max_len):
        #     if bin_entries [i] is None:
        #         print "no %s entry for %s" % (name, ("{:0" + str(max_len) + "b}").format(i))
        assert None not in bin_entries


    operand_type_to_bits = { 'b': 8,
                             'db': 16,
                             'w': 32,
                             'dw': 64,
                             'ew': 80 }

    operand_bits_to_type = { v: k for k, v in operand_type_to_bits.items() }


    operand_re = re.compile('(b|db|w|dw|ew|br)(\((r|w|rmw)\)){0,1}$')

    def parse_operands_string(self, operand_string, get_modes = False):
        branch_ref = False
        if len(operand_string) == 0:
            return [], branch_ref
        ops = operand_string.split(',')
        if ops[-1] == 'br':
            branch_ref = True
            ops = ops[:-1]
        modes = []
        if get_modes:
            for op in ops:
                m = operand_re.match(op)
                if m:
                    mode = m.group(3)
                else:
                    mode = 'r'
                modes += [mode]
        opl = [self.operand_type_to_bits[o] for o in ops]
        if get_modes:
            return opl, modes, branch_ref
        else:
            return opl, branch_ref

    def operand_strip_mode(self, operand_string):
        m = self.operand_re.match(operand_string)
        if m:
            return m.group(1)
        else:
            return ""

    def operands_strip_modes(self, operands_string):
        return ','.join([self.operand_strip_mode(op) for op in operands_string.split(',')])

    def parse_class_enum(self, class_enum):
        self.class_by_operands = {}
        self.class_by_encoding = {}
        classes = self.get_elements_dict(class_enum, 'constant')
        for operands in classes:
            reserved = operands.startswith('rsv')
            encoding = self.size_and_value(classes[operands] ['encoding'])
            if reserved:
                refs, branch_ref = [ ], False
            else:
                refs, branch_ref = self.parse_operands_string(operands)
                assert operands not in self.class_by_operands
            assert encoding not in self.class_by_encoding
            c = self.class_t(encoding, reserved, refs, branch_ref, { })
            self.class_by_operands [operands] = c
            self.class_by_encoding [encoding] = c
        self.validate_encodings(self.class_by_encoding, 'class')

    def parse_format_enum(self, format_enum):
        self.format_by_operands = {}
        self.format_by_order_encoding = [{ }, { }, { }, { }]
        formats = self.get_elements_dict(format_enum, 'constant')
        for operands in formats:
            if len(operands) == 0:
                operand_list = [ ]
            else:
                operand_list = operands.split(',')
            order = len(operand_list)
            encoding = self.size_and_value (formats[operands] ['encoding'])
            f = self.format_t(encoding, operand_list)
            assert operands not in self.format_by_operands
            assert encoding not in self.format_by_order_encoding [order]
            self.format_by_operands [operands] = f
            self.format_by_order_encoding [order] [encoding] = f
        for order in range(1, 4):
            self.validate_encodings(self.format_by_order_encoding [order], 'format(%d)' % order)


    def parse_operator_enum(self, operator_enum):
        #self.operator_by_name = {}
        self.operator_by_id = {}
        operator_elems = self.get_elements_dict(operator_enum, 'operator')
        for name in operator_elems:
            operator_elem = operator_elems[name]
            id = int(operator_elem['id'])
            operands = self.operands_strip_modes(operator_elem['operands'])
            encoding = self.size_and_value(operator_elem['encoding'])
            clas = self.class_by_operands [operands]
            if id in self.operator_by_id:
                operator = self.operator_by_id [id]
                assert name not in operator.names
                assert id == operator.id
                assert clas == operator.clas
                assert encoding == operator.encoding
                operator.names.append(name)
            else:
                operator = self.operator_t([name], id, clas, encoding)
                self.operator_by_id [id] = operator
                # also add operator to class operator dict
                assert encoding not in clas.operators
                clas.operators [encoding] = operator
        # validate per-class opcode dicts
        for operands in self.class_by_operands:
            self.validate_encodings(self.class_by_operands[operands].operators, 'class(%s)' % str(clas.encoding))


    def parse_instruction_set(self, instruction_set):
        self.parse_class_enum(self.get_single_named_element(instruction_set, 'enumeration', 'class'))
        self.parse_format_enum(self.get_single_named_element(instruction_set, 'enumeration', 'format'))
        self.parse_operator_enum(self.get_single_named_element(instruction_set, 'enumeration', 'operator'))


    def __init__(self, d432_tree):
        d432_root = d432_tree.getroot()
        self.symbols = { }

        for child in d432_root:
            name = child.get('name')
            if child.tag == 'instruction_set':
                self.parse_instruction_set(child)
            elif child.tag == 'enumeration':
                if name in self.symbols:
                    print "enumeration problem:", name
                assert name not in self.symbols
                self.symbols[name] = self.symbol_t(child.tag,
                                                   self.parse_enumeration(child))
            elif child.tag == 'struct' or child.tag == 'union':
                assert name not in self.symbols
                self.symbols[name] = self.symbol_t(child.tag,
                                                   self.get_struct(child))
            elif child.tag == 'segment':
                assert name not in self.symbols

                base_type = child.get('base_type')
                assert self.is_enumeration_element('base_type', base_type)

                system_type = child.get('system_type')
                assert self.is_enumeration_element('system_type', system_type)

                self.symbols[name] = self.symbol_t(child.tag,
                                                   self.segment_t(base_type,
                                                                  system_type))


def gen_operator_h(arch, f):
    f.write('// Automatically generated - do not edit!\n')
    f.write('\n')

    f.write('typedef struct class_info_t class_info_t;\n')
    f.write('\n')

    f.write('typedef struct operator_info_t operator_info_t;\n')
    f.write('\n')

    f.write('typedef void operator_fn_t (class_info_t *class_info,\n')
    f.write('                            operator_info_t *operator_info);\n')
    f.write('\n')

    f.write('typedef enum\n')
    f.write('{\n')
    for x in ['  op_len_%s,\n' % x for x in ['none', '8', '16', '32', '64', '80']]:
        f.write(x)
    f.write('} operand_len_t;\n')
    f.write('\n')

    f.write('struct operator_info_t\n')
    f.write('{\n')
    f.write('  int opcode_bit_len;\n')
    f.write('  int operator_id;\n')
    f.write('  operator_fn_t *operator_fn;\n');
    f.write('};\n')
    f.write('\n')

    f.write('typedef struct class_info_t\n')
    f.write('{\n')
    f.write('  int class_bit_len;\n')
    f.write('  int order;\n')
    f.write('  operand_len_t operand_len [3];\n')
    f.write('  bool branch_ref;\n')
    f.write('  int opcode_mask;\n')
    f.write('  const operator_info_t *operator_info;\n')
    f.write('} class_info_t;\n')
    f.write('\n')

    for id in arch.operator_by_id:
        operator = arch.operator_by_id[id]
        f.write('  /* %3d */ operator_fn_t op_%s;' % (id, operator.names [0]))
        if len(operator.names) > 1:
            f.write(' // also %s' % ', '.join(operator.names[1:]))
        f.write('\n')
    f.write('\n')


def gen_operator_c(arch, f):
    f.write('#include <stdbool.h>\n')
    f.write('\n')

    f.write('#include "operator.h"\n')
    f.write('\n')

    for id in arch.operator_by_id:
        operator = arch.operator_by_id[id]
        f.write('/* %3d */\n' % id)
        f.write('void op_%s (class_info_t *class_info, operator_info_t *operator_info)\n' % operator.names [0])
        if len(operator.names) > 1:
            f.write('/* also %s */\n' % ', '.join(operator.names[1:]))
        f.write('{\n')
        f.write('  ; /* XXX more code needed here */\n')
        f.write('}\n');
        f.write('\n')

def gen_tables_c(arch, f):
    f.write('// Automatically generated - do not edit!\n')
    f.write('\n')

    f.write('#include <stdbool.h>\n')
    f.write('\n')

    f.write('#include "operator.h"\n')
    f.write('\n')

    # write opcode tables, one per class
    for class_encoding in sorted(arch.class_by_encoding.keys(), key = lambda x: str(x)[::-1]):
        clas = arch.class_by_encoding[class_encoding]
        f.write('// opcode table for class %s: %s' % (str(class_encoding), ','.join([arch.operand_bits_to_type[bits] for bits in clas.refs])))
        if clas.branch_ref:
            if len(clas.refs) > 0:
                f.write(',')
            f.write('br')
        f.write('\n')
        operators = arch.expand_encoding_dict(clas.operators)
        f.write('const operator_info_t class_%s_opcode_table [%d] =\n' % (str(class_encoding), len(operators)))
        f.write('{\n')
        for i in range(len(operators)):
            f.write('  /* %5s */ { %d, %3d, op_%s },\n' % (str(operators[i].encoding),
                                                         operators[i].encoding.size,
                                                         operators[i].id,
                                                         operators[i].names[0]));
        f.write('};\n')
        f.write('\n')
    f.write('\n')

    # write class table
    classes = arch.expand_encoding_dict(arch.class_by_encoding)
    f.write('const class_info_t class_info[%d] =\n' % len(classes))
    f.write('{\n')
    for clas in classes:
        opcode_table_name = 'class_%s_opcode_table' % str(clas.encoding)
        f.write('  /* %6s */ { %d, %d, { '  % (str(clas.encoding),
                                               clas.encoding.size,
                                               len(clas.refs)))
        for i in range(len(clas.refs)):
            if i != 0:
                f.write(', ')
            f.write('op_len_%s' % clas.refs[i])
        f.write(' }, %s, %d, %s },\n' % (str(clas.branch_ref).lower(),
                                         (1 << arch.max_encoding_len(clas.operators)) - 1,
                                         opcode_table_name))
    f.write('};\n')
    f.write('\n')



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='iAPX 432 Architecture Parser')
    parser.add_argument('-a', '--arch',
                        type=argparse.FileType('r', 0),
                        default='definitions.xml',
                        help='architecture definition (XML)')
    parser.add_argument('--gen-operator-h',
                        nargs='?',
                        type=argparse.FileType('w', 0),
                        const='operator.h',
                        help='generate C operator definitions header file')
    parser.add_argument('--gen-operator-c',
                        nargs='?',
                        type=argparse.FileType('w', 0),
                        const='operator.c',
                        help='generate C operator definitions source file')
    parser.add_argument('--gen-tables-c',
                        nargs='?',
                        type=argparse.FileType('w', 0),
                        const='tables.c',
                        help='generate C tables source file')

    args = parser.parse_args()

    arch_tree = xml.etree.ElementTree.parse(args.arch)
    args.arch.close()
    arch = arch(arch_tree)

    if args.gen_operator_h:
        gen_operator_h(arch, args.gen_operator_h)
        args.gen_operator_h.close()

    if args.gen_operator_c:
        gen_operator_c(arch, args.gen_operator_c)
        args.gen_operator_c.close()

    if args.gen_tables_c:
        gen_tables_c(arch, args.gen_tables_c)
        args.gen_tables_c.close()

