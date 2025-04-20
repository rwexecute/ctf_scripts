#!/usr/bin/env python3

import argparse
from signify.authenticode import SignedPEFile

def get_authenticode_info(fh):

    p_name = 'n/a'
    p_time = 'n/a'

    with open(fh, "rb") as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.signed_datas:
            p_name = signed_data.signer_info.program_name
            if signed_data.signer_info.countersigner is not None:
                p_time = signed_data.signer_info.countersigner.signing_time
    
    return p_name, p_time

def main():
    parser = argparse.ArgumentParser(description="Extract the programname and timestamp from a PECOFF files certificate")
    parser.add_argument("filepath", help="Path to the PE file (e.g., .exe, .dll)")

    args = parser.parse_args()
    p_name, p_time = get_authenticode_info(args.filepath)

    print(f"Programname: {p_name}")
    print(f"Timestamp: {p_time}")

if __name__ == '__main__':
    main()
