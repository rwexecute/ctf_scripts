#!/usr/bin/env python3

import pefile
import uuid
import argparse
import sys
import struct

def get_debug_info(filepath):
    try:
        pe = pefile.PE(filepath)

        if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            print("The PE file does not contain a debug directory.")
            return None

        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            debug_data = pe.__data__[entry.struct.PointerToRawData:
                                      entry.struct.PointerToRawData + entry.struct.SizeOfData]

            if debug_data[:4] == b'RSDS':
                guid_bytes = debug_data[4:20]
                age = struct.unpack("<I", debug_data[20:24])[0]

                try:
                    pdb_path = debug_data[24:].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                except Exception:
                    pdb_path = "<Failed to decode>"

                guid = uuid.UUID(bytes_le=guid_bytes)
                timestamp = entry.struct.TimeDateStamp

                return {
                    "GUID": str(guid),
                    "PDB Path": pdb_path,
                    "Timestamp": timestamp,
                    "Age": age
                }

        print("No CodeView (RSDS) debug info found in debug directory.")
        return None

    except FileNotFoundError:
        print(f"File not found: {filepath}")
        sys.exit(1)
    except pefile.PEFormatError as e:
        print(f"Invalid PE file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Extract GUID, PDB path, timestamp, and age from a PE/COFF file's debug directory.")
    parser.add_argument("filepath", help="Path to the PE file (e.g., .exe, .dll)")

    args = parser.parse_args()
    info = get_debug_info(args.filepath)

    if info:
        print(f"PE GUID:    {info['GUID']}")
        print(f"PDB Path:   {info['PDB Path']}")
        print(f"Timestamp:  {info['Timestamp']}")
        print(f"Age:        {info['Age']}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
