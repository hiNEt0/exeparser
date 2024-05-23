import pefile
import argparse


def parse_pe(args):
    try:
        pe = pefile.PE(args.file)
    except FileNotFoundError:
        print(f"File not found: {args.file}")
        return
    except pefile.PEFormatError:
        print(f"File is not a valid PE file: {args.file}")
        return

    print(f"File: {args.file}")
    print(f"Magic: {hex(pe.DOS_HEADER.e_magic)}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
    print(f"Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}")

    if args.optional:
        print("\nOptional Header:")
        print(f"  Address of Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"  Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"  Section Alignment: {pe.OPTIONAL_HEADER.SectionAlignment}")
        print(f"  File Alignment: {pe.OPTIONAL_HEADER.FileAlignment}")
        print(f"  Size of Image: {pe.OPTIONAL_HEADER.SizeOfImage}")
        print(f"  Size of Headers: {pe.OPTIONAL_HEADER.SizeOfHeaders}")
        print(f"  Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        print(f"  Dll Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
        print(f"  Number of Rva and Sizes: {pe.OPTIONAL_HEADER.NumberOfRvaAndSizes}")

    if args.directories:
        print("\nData Directories:")
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            print(f"  {directory.name}: VirtualAddress: {hex(directory.VirtualAddress)}, Size: {directory.Size}")

    if args.sections:
        print("\nSections:")
        for section in pe.sections:
            print(f"  Name: {section.Name.decode().strip()}")
            print(f"  Virtual Address: {hex(section.VirtualAddress)}")
            print(f"  Virtual Size: {section.Misc_VirtualSize}")
            print(f"  Raw Size: {section.SizeOfRawData}")
            print(f"  Characteristics: {hex(section.Characteristics)}")
            print("  -------------------------")


def main():
    parser = argparse.ArgumentParser(
        description="Parse and display the structure of a PE file."
    )
    parser.add_argument(
        "file",
        help="path to the PE file"
    )
    parser.add_argument(
        "-o",
        "--optional",
        action="store_true",
        help="show optional header"
    )
    parser.add_argument(
        "-d",
        "--directories",
        action="store_true",
        help="display information about each data directory: directory name, virtual address and size"
    )
    parser.add_argument(
        "-s",
        "--sections",
        action="store_true",
        help="display information about each section"
    )
    args = parser.parse_args()

    parse_pe(args)


if __name__ == "__main__":
    main()
