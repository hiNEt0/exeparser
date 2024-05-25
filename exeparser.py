import argparse
import struct


def parse_pe(args):
    with open(args.file, 'rb') as f:
        # DOS header --------------------------
        dos_header = f.read(64)

        # 2s - stands for 2 character string (need to be 'MZ' for PE files)
        # 58x - skip 58 bytes
        # I - take 4 bytes as unsigned int
        e_magic, e_lfanew = struct.unpack_from('2s58xI', dos_header)

        if e_magic != b'MZ':
            print(f"File is not a valid PE file: {args.file}")
            return

        print(f"File: {args.file}")
        print(f"Magic: {e_magic}")

        # PE header ---------------------------
        f.seek(e_lfanew)
        pe_header = f.read(24)

        # 4s - stands for 4 character string (expected b'PE\x00\x00')
        # 2H - next 4 bytes are interpreted as two 16-bit unsigned ints (x2)
        # 3I - next 12 bytes are interpreted as three 32-bit unsigned ints
        signature, machine, number_of_sections, time_date_stamp, \
            pointer_to_symbol_table, number_of_symbols, size_of_optional_header, \
            characteristics = struct.unpack('4s2H3I2H', pe_header)

        print(f"Number of Sections: {number_of_sections}")
        print(f"Characteristics: {hex(characteristics)}")
        print(f"Time Date Stamp: {time_date_stamp}")

        # Optional header ---------------------
        if args.optional:
            optional_header = f.read(size_of_optional_header)

            # B - 8-bit unsigned int (unsigned char)
            magic, major_linker_version, minor_linker_version, size_of_code, \
                size_of_initialized_data, size_of_uninitialized_data, \
                address_of_entry_point, base_of_code, base_of_data, image_base, \
                section_alignment, file_alignment, major_os_version, minor_os_version, \
                major_image_version, minor_image_version, major_subsystem_version, \
                minor_subsystem_version, win32_version_value, size_of_image, \
                size_of_headers, checksum, subsystem, dll_characteristics, \
                size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, \
                size_of_heap_commit, loader_flags, number_of_rva_and_sizes = \
                struct.unpack('H2B5I6H6I2H8I', optional_header[:96])

            print("\nOptional Header:")
            print(f"  Address of Entry Point: {hex(address_of_entry_point)}")
            print(f"  Image Base: {hex(image_base)}")
            print(f"  Section Alignment: {section_alignment}")
            print(f"  File Alignment: {file_alignment}")
            print(f"  Size of Image: {size_of_image}")
            print(f"  Size of Headers: {size_of_headers}")
            print(f"  Subsystem: {subsystem}")
            print(f"  Dll Characteristics: {hex(dll_characteristics)}")
            print(f"  Number of Rva and Sizes: {number_of_rva_and_sizes}")

        # Data directories --------------------
        if args.directories:
            print("\nData Directories:")

            # first 96 bytes have already been unpacked earlier for other fields
            # number_of_rva_and_sizes contains the number of data directories
            # each data directory is 8 bytes (4 bytes for virtual address and 4 bytes for size)
            data_directories = optional_header[96:96 + 8 * number_of_rva_and_sizes]
            for i in range(number_of_rva_and_sizes):
                virtual_address, size = struct.unpack_from('II', data_directories, i * 8)
                print(f"  Directory {i}: VirtualAddress: {hex(virtual_address)}, Size: {size}")

        # Sections ----------------------------
        if args.sections:
            print("\nSections:")
            section_headers = []
            for i in range(number_of_sections):
                # Each section header takes exactly 40 bytes
                section = f.read(40)
                name, virtual_size, virtual_address, size_of_raw_data, \
                    pointer_to_raw_data, pointer_to_relocations, \
                    pointer_to_line_numbers, number_of_relocations, \
                    number_of_line_numbers, characteristics = \
                    struct.unpack('8s6I2HI', section)
                section_headers.append({
                    'Name': name.decode().strip(),
                    'VirtualAddress': virtual_address,
                    'VirtualSize': virtual_size,
                    'RawSize': size_of_raw_data,
                    'Characteristics': characteristics
                })

            for section in section_headers:
                print(f"  Name: {section['Name']}")
                print(f"  Virtual Address: {hex(section['VirtualAddress'])}")
                print(f"  Virtual Size: {section['VirtualSize']}")
                print(f"  Raw Size: {section['RawSize']}")
                print(f"  Characteristics: {hex(section['Characteristics'])}")
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
