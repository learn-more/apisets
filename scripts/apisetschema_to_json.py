'''
PROJECT:     Apiset info
LICENSE:     MIT (https://spdx.org/licenses/MIT)
PURPOSE:     Convert apisets into json descriptors
COPYRIGHT:   Copyright 2019 Mark Jansen (mark.jansen@reactos.org)
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
            'Version': '{}-{}'.format(self.ProductVersion, self.arch),
            'md5': self.md5sum,
            'InternalName': self.InternalName,
            'CompanyName': self.CompanyName,
            'FileDescription': self.FileDescription,
            'FileVersion': self.FileVersion,
            'ProductVersion': self.ProductVersion,
            'PeChecksum': self.CheckSum,
            'Size': self.Size,
            'Machine': self.arch
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
    filename = '{}.json'.format(name)
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / filename, 'w') as json_file:
        dump(obj, json_file, indent='  ')
    return name


def get_forwarders(pe):
    dirs = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
    pe.parse_data_directories(directories=dirs)
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        assert not exp.forwarder
        if exp.name:
            assert not exp.forwarder_offset
        curr_export = {
            'ord': exp.ordinal
        }
        if exp.name:
            curr_export['name'] = exp.name.decode('utf-8')
        exports.append(curr_export)
    return exports


def process_apisets_dir(input_dir, output_dir, version_parent):
    target_dir = output_dir / version_parent
    target_dir.mkdir(parents=True, exist_ok=True)
    for filename in Path(input_dir).glob('**/*.dll'):
        pe = pefile.PE(filename, fast_load=True)

        info = PeInfo(pe)
        if not info.ProductVersion:
            print('No version found in', input_file)
            continue

        obj = info.as_json()
        exports = get_forwarders(pe)
        obj['exports'] = exports
        output_file = target_dir / '{}.json'.format(filename.stem)
        with open(output_file, 'w') as json_file:
            dump(obj, json_file, indent='  ')


class ApisetSource:
    def __init__(self, version, directory):
        self.version = version
        self.directory = directory


def write_schemas(input_dir, output_dir):
    sources = []
    for filename in Path(input_dir).glob('**/apisetschema.dll'):
        version = process_schema_file(filename, output_dir / 'apisetschema')
        sources.append(ApisetSource(version, filename.parent))
    return sources


def main(input_dir, output_dir, content_dir):
    sources = write_schemas(input_dir, output_dir)
    apisets_dir = output_dir / 'apisets'
    for source in sources:
        apisets = source.directory / 'apisets'
        if apisets.is_dir():
            process_apisets_dir(apisets, apisets_dir, source.version)
    hugo_pages_from_data.pages_from_data(output_dir, content_dir)


if __name__ == '__main__':
    main(input_dir= DEFAULTINPUTDIR, output_dir= DEFAULTDATADIR, content_dir= DEFAULTCONTENTDIR)
