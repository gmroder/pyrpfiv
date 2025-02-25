# pyrpfiv

A Python library for parsing and modifying RPF (Resource Package Format) files, specifically designed for Grand Theft Auto IV. This library provides simple functionality to read, extract, and modify files within RPF archives while handling encryption and file name hashing.

## Table of Contents

### Core Functions

- [File Extraction](#extracting-files) - Extract files from RPF archives
- [File Replacement](#replacing-files) - Replace files in RPF archives
- [File Listing](#listing-files) - List all files in RPF archives
- [JSON Export](#exporting-rpf-contents) - Export RPF contents to JSON

### Setup & Requirements

- [Installation](#installation)
- [Requirements](#requirements)
- [Basic Usage](#basic-usage)

### Documentation

- [API Reference](#api-reference)
- [Error Handling](#error-handling)
- [Technical Details](#technical-details)
- [Version Support](#version-support)

### Additional Information

- [File Structure Requirements](#file-structure-requirements)
- [Disclaimer](#disclaimer)
- [License](#license)

## Features

- Parse RPF3 file format used in GTA IV
- Extract files from RPF archives
- Add/Replace files in RPF archives while preserving hash structure
- Automatic handling of encrypted TOC (Table of Contents)
- Support for file name hash resolution using hashes.ini
- JSON export of RPF contents
- Detailed logging of operations

## Installation

```bash
pip install pyrpfiv
```

## Requirements

- Python 3.8 or higher
- pycryptodome >= 3.19.0
- GTA IV executable version 1.0.8.0, 1.2.0.43, or 1.2.0.59 (other versions are not supported)
- hashes.ini file in working directory (for filename resolution)

## Basic Usage

```python
from pyrpfiv import RPFParser

# Initialize parser with RPF file and GTA IV executable path
parser = RPFParser(
    rpf_filename="path/to/your.rpf",
    gtaiv_exe_path="path/to/gtaiv.exe"  # Must be version 1.0.8.0, 1.2.0.43, or 1.2.0.59
)
```

## API Reference

### RPFParser Class

#### Initialization

```python
parser = RPFParser(rpf_filename: str, gtaiv_exe_path: str)
```

- `rpf_filename`: Path to the RPF file you want to work with
- `gtaiv_exe_path`: Path to GTA IV executable (versions 1.0.8.0, 1.2.0.43, or 1.2.0.59 supported for AES key extraction)

#### File Operations

##### Extracting Files

```python
parser.extract_file(
    file_path="RADIO_VLADIVOSTOK/track_01",  # Note: RPF files don't use extensions
    output_dir="output/directory"
)
```

- `file_path`: Path of the file within the RPF archive
- `output_dir`: Directory where the file should be extracted

##### Replacing Files

```python
parser.add_file(
    source_file="path/to/new/audio",
    rpf_path="RADIO_VLADIVOSTOK/track_01"  # Note: RPF files don't use extensions
)
```

- `source_file`: Path to the new file that will replace the existing one
- `rpf_path`: Path of the file to replace within the RPF archive

##### Listing Files

```python
# Access all files in the RPF
for entry in parser.paths:
    print(f"File: {entry['path']}")
    print(f"Size: {entry['size']} bytes")
    print(f"Offset: 0x{entry['offset']:X}")
```

##### Exporting RPF Contents

```python
# Export to JSON
parser.save_json("rpf_contents.json")
```

### File Structure Requirements

#### hashes.ini

The library requires a `hashes.ini` file in the working directory for resolving file name hashes. Format:

```ini
hash_value=filename
# Example:
123456789=track_01
```

### Error Handling

The library provides several custom exceptions for proper error handling:

- `RPFParsingError`: General parsing errors
- `FileExtractionError`: File extraction failures
- `FileNotFoundInRPFError`: File not found in RPF archive
- `HashesFileNotFoundError`: Missing hashes.ini file
- `InvalidTOCEntryError`: Invalid TOC entry
- `AESKeyExtractionError`: Failed to extract AES key
- `TOCDecryptionError`: Failed to decrypt TOC

Example error handling:

```python
from pyrpfiv import RPFParser, FileNotFoundInRPFError

try:
    parser.extract_file("nonexistent/file", "output")
except FileNotFoundInRPFError as e:
    print(f"Error: {e}")
```

## Technical Details

### Version Support

Currently, GTA IV versions 1.0.8.0, 1.2.0.43, and 1.2.0.59 are supported. The AES key extraction is specifically tailored for these versions of the executable. Other versions of GTA IV will not work with this library.

## Disclaimer

This tool is provided for educational and research purposes only. The RPF file format is proprietary to Rockstar Games. Users of this library should:

1. Respect Rockstar Games' intellectual property rights
2. Comply with Rockstar Games' terms of service and EULA
3. Only use this tool with legally obtained copies of GTA IV versions 1.0.8.0, 1.2.0.43, or 1.2.0.59
4. Not use this tool for unauthorized distribution or modification of game files

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Special thanks to:

- [ahmed605's SparkIV](https://github.com/ahmed605/SparkIV) for providing valuable reference for RPF file format handling
- [dexyfex's CodeWalker](https://github.com/dexyfex/CodeWalker) for providing additional technical insights into the file format
