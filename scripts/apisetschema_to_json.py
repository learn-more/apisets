'''
PROJECT:     Apiset info
LICENSE:     MIT (https://spdx.org/licenses/MIT)
PURPOSE:     Convert apisetschema.dll files into json descriptors
COPYRIGHT:   Copyright 2019-2023 Mark Jansen (mark.jansen@reactos.org)
'''

from pathlib import Path
import pefile
from hashlib import md5
from json import dump
import apisetschema
import hugo_pages_from_data

SCRIPTDIR = Path(__file__).parent
DEFAULTDATADIR = Path(SCRIPTDIR).parent / 'data'
DEFAULTINPUTDIR = Path(SCRIPTDIR).parent / 'bin'
DEFAULTCONTENTDIR = Path(SCRIPTDIR).parent / 'content'

def winver_to_name(version):
    major, minor, build, _ = map(int, version.split('.'))
    if (major, minor) == (6, 0):
        return 'Vista'
    if (major, minor) == (6, 1):
        return 'Win7'
    if (major, minor) == (6, 2):
        return 'Win8'
    if (major, minor) == (6, 3):
        return 'Win8.1'
    if (major, minor) == (10, 0):
        if build < 22000:
            return 'Win10'
        return 'Win11'
    assert False, (major, minor, build)


def friendly_name(version, arch):
    arch = { 'AMD64': 'x64', 'I386': 'x86' }[arch]
    return winver_to_name(version) + '-' + arch


def value_or_none(table, name):
    value = table.entries.get(name, None)
    if value:
        return value.decode('UTF-8')
    return None


class PeInfo:
    def __init__(self, pe):
        self.CompanyName = None
        self.FileDescription = None
        self.FileVersion = None
        self.InternalName = None
        self.ProductVersion = None
        self._get_version(pe)
        arch = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        self.arch = arch[len('IMAGE_FILE_MACHINE_'):]
        # Calculate the md5 from the (internal) raw data of the PE file
        hasher = md5()
        hasher.update(pe.__data__)
        self.md5sum = hasher.hexdigest()
        self.CheckSum = pe.OPTIONAL_HEADER.CheckSum
        self.Size = len(pe.__data__)

    def _get_version(self, pe):
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        for root in pe.FileInfo:
            for stringtables in [fileinfo.StringTable for fileinfo in root if fileinfo.Key == b'StringFileInfo']:
                for table in stringtables:
                    self.CompanyName = value_or_none(table, b'CompanyName')
                    self.FileDescription = value_or_none(table, b'FileDescription')
                    self.FileVersion = value_or_none(table, b'FileVersion')
                    self.InternalName = value_or_none(table, b'InternalName')
                    self.ProductVersion = value_or_none(table, b'ProductVersion')

    def as_json(self):
        obj = {
            'Version': friendly_name(self.ProductVersion, self.arch),# '{}-{}'.format(self.ProductVersion, self.arch),
            'md5': self.md5sum,
            'PE': {
                'InternalName': self.InternalName,
                'CompanyName': self.CompanyName,
                'FileDescription': self.FileDescription,
                'FileVersion': self.FileVersion,
                'ProductVersion': self.ProductVersion,
                'Checksum': self.CheckSum,
                'Size': self.Size,
                'Machine': self.arch
            }
        }
        return obj


def process_schema_file(input_file, output_dir):
    pe = pefile.PE(input_file)

    apiset = next((section for section in pe.sections if section.Name == b'.apiset\x00'), None)
    if not apiset:
        print('No apiset section found in', input_file)
        return

    info = PeInfo(pe)
    if not info.ProductVersion:
        print('No version found in', input_file)
        return

    name = '{}-{}'.format(info.ProductVersion, info.arch)
    print('Generating apisetschema for', name)

    parser = apisetschema.Parser(apiset.get_data())
    hdr = parser.header()
    namespaces = []
    for namespace in parser.namespaces(hdr):
        vals = []
        val_hdr = parser.value_header(namespace)
        for value in parser.values(val_hdr):
            vals.append({'name': value.name, 'value': value.value, 'flags': value.flags})
        ns = {
            'name': namespace.name,
            'host': vals[0]['value'],
            'flags': namespace.flags
        }
        assert vals[0]['name'] == ''
        if len(vals) > 1:
            assert len(vals) == 2
            ns['alt_name'] = vals[1]['name']
            ns['alt_host'] = vals[1]['value']
        namespaces.append(ns)
    obj = info.as_json()
    obj['namespaces_count'] = hdr.count
    obj['namespaces'] = namespaces
    # Hack for natural ordering...
    if name.startswith('6.'):
        name = '0' + name
    filename = '{}.json'.format(name.lower())
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / filename, 'w') as json_file:
        dump(obj, json_file, indent='  ')
    return name

def write_schemas(input_dir, output_dir):
    for filename in Path(input_dir).glob('**/apisetschema.dll'):
        process_schema_file(filename, output_dir / 'apisetschema')


def main(input_dir, output_dir, content_dir):
    write_schemas(input_dir, output_dir)
    hugo_pages_from_data.pages_from_schemas(output_dir / 'apisetschema', content_dir / 'apisetschemas')


if __name__ == '__main__':
    main(input_dir= DEFAULTINPUTDIR, output_dir= DEFAULTDATADIR, content_dir= DEFAULTCONTENTDIR)
