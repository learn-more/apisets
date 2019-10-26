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

SCRIPTDIR = Path(__file__).parent
DEFAULTDATADIR = Path(SCRIPTDIR).parent / 'data'
DEFAULTINPUTDIR = Path(SCRIPTDIR).parent / 'bin'


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

    name = '{}-{}'.format(version, arch)
    print('Generating apiset for', name)

    # Calculate the md5 from the (internal) raw data of the PE file
    hasher = md5()
    hasher.update(pe.__data__)
    md5sum = hasher.hexdigest()

    parser = apisetschema.Parser(apiset.get_data())
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
    filename = '{}.json'.format(name)
    with open(Path(output_dir) / filename, 'w') as json_file:
        dump(obj, json_file, indent='  ')



def main(input_dir, output_dir):
    for filename in Path(input_dir).glob('**/apisetschema.dll'):
        process_file(filename, output_dir)

if __name__ == '__main__':
    main(input_dir= DEFAULTINPUTDIR, output_dir= DEFAULTDATADIR)
