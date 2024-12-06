import os
import struct
import json

from .constants import HEADER_SIZE, TOC_START_OFFSET, ENTRY_SIZE
from .crypto import extract_aes_key, decrypt_toc
from .exceptions import (
    RPFParsingError,
    FileExtractionError,
    FileNotFoundInRPFError,
    HashesFileNotFoundError,
    InvalidTOCEntryError,
)
from Crypto.Cipher import AES


class RPFParser:
    def __init__(self, rpf_filename, gtaiv_exe_path):
        self.rpf_filename = rpf_filename
        self.gtaiv_exe_path = gtaiv_exe_path
        self.entries = []
        self.known_filenames = {}
        self.paths = []
        self.aes_key = None
        self.init_known_filenames()
        self.aes_key = extract_aes_key(self.gtaiv_exe_path)
        self.parse()

    def init_known_filenames(self):
        """Initialize known filenames from 'hashes.ini'."""
        self.known_filenames = {}
        package_dir = os.path.dirname(os.path.abspath(__file__))
        hashes_path = os.path.join(package_dir, 'hashes.ini')
        
        if os.path.exists(hashes_path):
            print("\nLoading hashes.ini...")
            with open(hashes_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and '=' in line:
                        hash_str, name = line.split('=', 1)
                        try:
                            hash_value = int(hash_str)
                            self.known_filenames[hash_value] = name
                            print(f"Loaded hash mapping: {hash_str} -> {name}")
                        except ValueError:
                            print(f"Failed to parse line: {line}")
            print(f"\nTotal hash mappings loaded: {len(self.known_filenames)}")
        else:
            raise HashesFileNotFoundError(
                f'hashes.ini not found at {hashes_path}. Some filenames may not be resolved.'
            )

    def get_name(self, name_hash):
        """Gets the name of an entry."""
        return self.known_filenames.get(name_hash, f'0x{name_hash:X}')

    def parse(self):
        """Main parsing function."""
        with open(self.rpf_filename, 'rb') as f:
            header_data = f.read(HEADER_SIZE)
            identifier = header_data[0:4].decode('ascii')
            toc_size, entry_count, unknown, encrypted = struct.unpack('<IiiI', header_data[4:20])

            print(f"RPF Version: {identifier}")
            print(f"TOC Size: {toc_size}")
            print(f"Entry Count: {entry_count}")
            print(f"Encrypted: {encrypted != 0}")

            f.seek(TOC_START_OFFSET)
            toc_data = f.read(toc_size)

            if encrypted != 0:
                toc_data = decrypt_toc(toc_data, self.aes_key)
                print("TOC data decrypted successfully.")

            self.entries = []

            print("\nParsing TOC entries:")
            for i in range(entry_count):
                offset = i * ENTRY_SIZE
                entry_data = toc_data[offset:offset + ENTRY_SIZE]
                if len(entry_data) != ENTRY_SIZE:
                    raise InvalidTOCEntryError(f"Invalid TOC entry size at index {i}")
                name_hash, data1, data2, unknown = struct.unpack('<IIII', entry_data)

                is_directory = (data2 & 0x80000000) != 0
                data2 &= 0x7FFFFFFF

                if is_directory:
                    entry = {
                        'type': 'directory',
                        'name_hash': name_hash,
                        'content_count': data1,
                        'content_index': data2,
                        'index': i,
                        'name': self.get_name(name_hash),
                    }
                    print(f"\nDirectory Entry {i}:")
                    print(f"  Name: {entry['name']}")
                    print(f"  Content Index: {entry['content_index']}")
                    print(f"  Content Count: {entry['content_count']}")
                else:
                    entry = {
                        'type': 'file',
                        'name_hash': name_hash,
                        'size': data1,
                        'offset': data2,
                        'index': i,
                        'name': self.get_name(name_hash),
                    }

                    print(f"File Entry {i}:")
                    print(f"  Name: {entry['name']}")
                    print(f"  Size: {entry['size']}")
                    print(f"  Offset: 0x{entry['offset']:X}")

                self.entries.append(entry)

            print(f"\nTotal entries parsed: {len(self.entries)}")
            self.build_file_list()

    def build_file_list(self):
        """Build a complete list of files with their paths"""
        directories = [entry for entry in self.entries if entry['type'] == 'directory']

        if not directories:
            print("No directories found!")
            return

        print("\nFound directories:")
        for dir_entry in directories:
            print(
                f"  {dir_entry['name']} (Index: {dir_entry['index']}, "
                f"Content Index: {dir_entry['content_index']}, "
                f"Count: {dir_entry['content_count']}")

        self.paths = []

        content_dir = next((dir for dir in directories if dir['index'] == 1), directories[0])
        print(f"\nProcessing directory: {content_dir['name']}")

        dir_files = [entry for entry in self.entries if entry['type'] == 'file']

        for entry in dir_files:
            path = f"{content_dir['name']}/{entry['name']}"
            self.paths.append({
                'path': path,
                'size': entry['size'],
                'offset': entry['offset']
            })
            print(f"Added file: {path}")

    def get_json_output(self, directories_=None):
        """Returns the RPF data in JSON format"""
        if directories_ is None:
            directories_ = {
                "rpf_info": {
                    "filename": self.rpf_filename,
                    "version": "RPF3",
                    "toc_size": 2048,
                    "entry_count": len(self.entries),
                    "encrypted": True
                },
                "directories": []
            }
        output = directories_

        files_by_dir = {}
        for entry in self.paths:
            dir_name, file_name = entry['path'].split('/', 1)
            if dir_name not in files_by_dir:
                files_by_dir[dir_name] = []

            files_by_dir[dir_name].append({
                "name": file_name,
                "size": entry['size'],
                "offset": f"0x{entry['offset']:X}"
            })

        for dir_name, files in files_by_dir.items():
            output["directories"].append({
                "name": dir_name,
                "files": sorted(files, key=lambda x: x['name'])
            })

        return output

    def save_json(self, output_file):
        """Save the RPF data to a JSON file."""
        json_data = self.get_json_output()
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        print(f"JSON data saved to {output_file}")

    def extract_file(self, file_path, output_dir):
        """Extract a specific file from the RPF archive."""
        file_entry = next((entry for entry in self.paths if entry['path'] == file_path), None)
        if not file_entry:
            raise FileNotFoundInRPFError(f"File not found in RPF archive: {file_path}")

        print(f"\nExtracting file:")
        print(f"Path: {file_path}")
        print(f"Size: {file_entry['size']} bytes")
        print(f"Offset: 0x{file_entry['offset']:X}")

        os.makedirs(output_dir, exist_ok=True)

        with open(self.rpf_filename, 'rb') as rpf:
            rpf.seek(0, 2)
            total_size = rpf.tell()
            print(f"Total RPF file size: 0x{total_size:X} bytes")
            rpf.seek(0)

            print(f"Current file position before seek: 0x{rpf.tell():X}")

            rpf.seek(file_entry['offset'])

            print(f"Position after seek: 0x{rpf.tell():X}")

            data = rpf.read(file_entry['size'])

            print(f"Bytes read: {len(data)}")

            output_path = os.path.join(output_dir, os.path.basename(file_path))
            with open(output_path, 'wb') as out_file:
                out_file.write(data)

            final_size = os.path.getsize(output_path)
            print(f"Final file size: {final_size} bytes")

        print(f"Extracted: {file_path} -> {output_path}")
        return True

    def add_file(self, source_file, rpf_path):
        """Replace a file in the RPF archive, preserving the original hash and structure."""
        if not os.path.exists(source_file):
            raise FileNotFoundError(f"Source file not found: {source_file}")

        existing_entry = next((entry for entry in self.paths if entry['path'] == rpf_path), None)
        if not existing_entry:
            raise FileNotFoundInRPFError(f"Target file not found in RPF: {rpf_path}")

        toc_entry = next(
            (
                entry
                for entry in self.entries
                if entry['type'] == 'file' and entry['offset'] == existing_entry['offset']
            ),
            None,
        )

        file_size = os.path.getsize(source_file)
        print(f"\nReplacing file {rpf_path}")
        print(f"Original size: {existing_entry['size']} bytes")
        print(f"New size: {file_size} bytes")
        print(f"Offset: 0x{existing_entry['offset']:X}")

        with open(source_file, 'rb') as f:
            file_data = f.read()

        with open(self.rpf_filename, 'rb+') as rpf:
            rpf.seek(TOC_START_OFFSET)
            original_toc = rpf.read(2048)

            encrypted = True
            if encrypted:
                original_toc = decrypt_toc(original_toc, self.aes_key)

            toc_data = bytearray(original_toc)

            rpf.seek(existing_entry['offset'])
            rpf.write(file_data)

            entry_index = toc_entry['index']

            entry_data = struct.pack(
                '<IIII',
                toc_entry['name_hash'],
                file_size,
                existing_entry['offset'],
                0,
            )

            toc_data[
            entry_index * ENTRY_SIZE: (entry_index * ENTRY_SIZE) + ENTRY_SIZE
            ] = entry_data

            if encrypted:
                cipher = AES.new(self.aes_key, AES.MODE_ECB)
                encrypted_toc = bytes(toc_data)
                for _ in range(16):
                    cipher = AES.new(self.aes_key, AES.MODE_ECB)
                    encrypted_toc = cipher.encrypt(encrypted_toc)
            else:
                encrypted_toc = bytes(toc_data)

            rpf.seek(TOC_START_OFFSET)
            rpf.write(encrypted_toc)

        existing_entry['size'] = file_size
        toc_entry['size'] = file_size

        print(f"Successfully replaced file: {rpf_path}")
        print(f"Hash preserved: 0x{toc_entry['name_hash']:X}")
