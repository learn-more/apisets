from pathlib import Path
import pefile
import struct
from hashlib import md5
from json import dump

# Based on info from https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm

SCRIPTDIR = Path(__file__).parent
DEFAULTDATADIR = Path(SCRIPTDIR).parent / 'data'
DEFAULTINPUTDIR = Path(SCRIPTDIR).parent / 'bin'

def read_string(data, offset, len):
    return data[offset:offset+len].decode('utf-16')


class API_SET_NAMESPACE_ARRAY:
    def __init__(self, version, count, dataoffset):
        self.version = version
        self.count = count
        self.dataoffset = dataoffset

    def __repr__(self):
        return 'NS: v{}, {} entries'.format(self.version, self.count)


class API_SET_NAMESPACE_ENTRY:
    def __init__(self, name, dataoffset, count=0):
        self.name = name
        self.dataoffset = dataoffset
        self.count = count

    def __repr__(self):
        return '{}: +0x{:x}'.format(self.name, self.dataoffset)


class API_SET_VALUE_ARRAY:
    def __init__(self, count, dataoffset):
        self.count = count
        self.dataoffset = dataoffset


class API_SET_VALUE_ENTRY:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class BaseParser:
    def parse(self, data):
        return self.parse_header(data)

    def namespace(self, data, offset):
        return self.parse_namespace(data, offset)


class Parser_2(BaseParser):
    namespace_header_format = '<II'
    namespace_format = '<III'
    value_header_format = '<I'
    value_format = '<IIII'

    def parse_header(self, data):
        Version, Count = struct.unpack_from(self.namespace_header_format, data)
        Offset = struct.calcsize(self.namespace_header_format)
        return API_SET_NAMESPACE_ARRAY(Version, Count, Offset)

    def parse_namespace(self, data, offset):
        NameOffset, NameLength, DataOffset = struct.unpack_from(self.namespace_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        offset += struct.calcsize(self.namespace_format)
        return offset, API_SET_NAMESPACE_ENTRY(name, DataOffset)

    def parse_value_header(self, data, namespace):
        Count, = struct.unpack_from(self.value_header_format, data, namespace.dataoffset)
        offset = namespace.dataoffset + struct.calcsize(self.value_header_format)
        return API_SET_VALUE_ARRAY(Count, offset)

    def parse_value(self, data, offset):
        NameOffset, NameLength, ValueOffset, ValueLength = struct.unpack_from(self.value_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        value = read_string(data, ValueOffset, ValueLength)
        offset += struct.calcsize(self.value_format)
        return offset, API_SET_VALUE_ENTRY(name, value)


class Parser_4(BaseParser):
    namespace_header_format = '<IIII'
    namespace_format = '<IIIIII'
    value_header_format = '<II'
    value_format = '<IIIII'

    def parse_header(self, data):
        Version, Size, Flags, Count = struct.unpack_from(self.namespace_header_format, data)
        Offset = struct.calcsize(self.namespace_header_format)
        assert Flags == 0
        return API_SET_NAMESPACE_ARRAY(Version, Count, Offset)

    def parse_namespace(self, data, offset):
        Flags, NameOffset, NameLength, AliasOffset, AliasLength, DataOffset = struct.unpack_from(self.namespace_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        offset += struct.calcsize(self.namespace_format)
        return offset, API_SET_NAMESPACE_ENTRY(name, DataOffset)

    def parse_value_header(self, data, namespace):
        Flags, Count = struct.unpack_from(self.value_header_format, data, namespace.dataoffset)
        offset = namespace.dataoffset + struct.calcsize(self.value_header_format)
        return API_SET_VALUE_ARRAY(Count, offset)

    def parse_value(self, data, offset):
        Flags, NameOffset, NameLength, ValueOffset, ValueLength = struct.unpack_from(self.value_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        value = read_string(data, ValueOffset, ValueLength)
        offset += struct.calcsize(self.value_format)
        return offset, API_SET_VALUE_ENTRY(name, value)


class Parser_6(BaseParser):
    namespace_header_format = '<IIIIIII'
    namespace_format = '<IIIIII'
    value_format = '<IIIII'

    def parse_header(self, data):
        Version, Size, Flags, Count, OffsetArray, OffsetHash, Multiplier = struct.unpack_from(self.namespace_header_format, data)
        Offset = OffsetArray
        assert Flags == 0
        return API_SET_NAMESPACE_ARRAY(Version, Count, Offset)

    def parse_namespace(self, data, offset):
        Flags, NameOffset, NameLength, NameLengthMinusHyphen, DataOffset, NumberOfHosts = struct.unpack_from(self.namespace_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        offset += struct.calcsize(self.namespace_format)
        return offset, API_SET_NAMESPACE_ENTRY(name, DataOffset, NumberOfHosts)

    def parse_value_header(self, data, namespace):
        # v6 does not have a header, but has the required info encoded in the namespace
        return API_SET_VALUE_ARRAY(namespace.count, namespace.dataoffset)

    def parse_value(self, data, offset):
        Flags, NameOffset, NameLength, ValueOffset, ValueLength = struct.unpack_from(self.value_format, data, offset)
        name = read_string(data, NameOffset, NameLength)
        value = read_string(data, ValueOffset, ValueLength)
        offset += struct.calcsize(self.value_format)
        return offset, API_SET_VALUE_ENTRY(name, value)


class ApisetParser:
    def __init__(self, data):
        self.data = data
        version, = struct.unpack_from('<I', data)
        if version == 2:
            self.parser = Parser_2()
        elif version == 4:
            self.parser = Parser_4()
        elif version == 6:
            self.parser = Parser_6()
        else:
            assert False, "Unknown version " + str(version)

    def header(self):
        return self.parser.parse(self.data)

    def namespaces(self, header):
        data = self.data
        offset = header.dataoffset
        for n in range(header.count):
            offset, namespace = self.parser.parse_namespace(data, offset)
            yield namespace

    def value_header(self, namespace):
        data = self.data
        return self.parser.parse_value_header(data, namespace)

    def values(self, header):
        data = self.data
        offset = header.dataoffset
        for n in range(header.count):
            offset, value = self.parser.parse_value(data, offset)
            yield value


def get_version(pe):
    for root in pe.FileInfo:
        for stringtables in [fileinfo.StringTable for fileinfo in root if fileinfo.Key == b'StringFileInfo']:
            for table in stringtables:
                version = table.entries.get(b'ProductVersion', None)
                if version:
                    return version.decode('UTF-8')


def process_file(input_file, output_dir):
    pe = pefile.PE(input_file)

    arch = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
    arch = arch[len('IMAGE_FILE_MACHINE_'):]

    apiset = next((section for section in pe.sections if section.Name == b'.apiset\x00'), None)
    if not apiset:
        print('No apiset section found in', input_file)
        return

    # Get version from resources
    version = get_version(pe)
    if not version:
        print('No version found in', input_file)
        return

    # Calculate the md5 from the (internal) raw data of the PE file
    hasher = md5()
    hasher.update(pe.__data__)
    md5sum = hasher.hexdigest()

    parser = ApisetParser(apiset.get_data())
    hdr = parser.header()
    namespaces = []
    for namespace in parser.namespaces(hdr):
        vals = []
        val_hdr = parser.value_header(namespace)
        for value in parser.values(val_hdr):
            vals.append({'name': value.name, 'value': value.value})
        ns = {
            'name': namespace.name,
            'values_count': val_hdr.count,
            'values': vals
        }
        namespaces.append(ns)
    obj = {
        'Version': version,
        'md5': md5sum,
        'namespaces_count': hdr.count,
        'namespaces': namespaces
    }
    filename = '{}-{}.json'.format(version, arch)
    with open(Path(output_dir) / filename, 'w') as json_file:
        dump(obj, json_file, indent='  ')



def main(input_dir, output_dir):
    for filename in Path(input_dir).glob('**/*.dll'):
        process_file(filename, output_dir)

if __name__ == '__main__':
    main(input_dir= DEFAULTINPUTDIR, output_dir= DEFAULTDATADIR)
