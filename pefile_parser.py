import struct
from pefile import PE
import cxxfilt


class PEFile:
    def __init__(self, file_path):
        self.file_path = file_path
        self.dos_header = None
        self.pe_header = None
        self.optional_header = {}
        self.sections = []
        self.imports = []
        self.exports = []

    def parse(self):
        try:
            with open(self.file_path, 'rb') as f:
                self._parse_dos_header(f)
                self._parse_pe_header(f)
                self._parse_optional_header(f)
                self._parse_sections(f)
        except (OSError, IOError) as e:
            print(f"Error opening file: {e}")
        except struct.error as e:
            print(f"Error unpacking data: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def _parse_dos_header(self, f):
        try:
            self.dos_header = f.read(64)

            # 2s - stands for 2 character string (need to be 'MZ' for PE files)
            # 58x - skip 58 bytes
            # I - take 4 bytes as unsigned int
            self.e_magic, self.e_lfanew = struct.unpack_from('2s58xI', self.dos_header)
            if self.e_magic != b'MZ':
                raise ValueError(f"File is not a valid PE file: {self.file_path}")

        except struct.error as e:
            print(f"Error unpacking DOS header: {e}")
        except ValueError as e:
            print(e)

    def _parse_pe_header(self, f):
        try:
            f.seek(self.e_lfanew)
            self.pe_header = f.read(24)

            # 4s - stands for 4 character string (expected b'PE\x00\x00')
            # 2H - next 4 bytes are interpreted as two 16-bit unsigned ints (x2)
            # 3I - next 12 bytes are interpreted as three 32-bit unsigned ints
            self.signature, self.machine, self.number_of_sections, self.time_date_stamp, \
                self.pointer_to_symbol_table, self.number_of_symbols, self.size_of_optional_header, \
                self.characteristics = struct.unpack('4s2H3I2H', self.pe_header)

        except struct.error as e:
            print(f"Error unpacking PE header: {e}")

    def _parse_optional_header(self, f):
        try:
            self.optional_header = f.read(self.size_of_optional_header)

            # B - 8-bit unsigned int (unsigned char)
            self.magic, self.major_linker_version, self.minor_linker_version, self.size_of_code, \
                self.size_of_initialized_data, self.size_of_uninitialized_data, \
                self.address_of_entry_point, self.base_of_code, self.base_of_data, self.image_base, \
                self.section_alignment, self.file_alignment, self.major_os_version, self.minor_os_version, \
                self.major_image_version, self.minor_image_version, self.major_subsystem_version, \
                self.minor_subsystem_version, self.win32_version_value, self.size_of_image, \
                self.size_of_headers, self.checksum, self.subsystem, self.dll_characteristics, \
                self.size_of_stack_reserve, self.size_of_stack_commit, self.size_of_heap_reserve, \
                self.size_of_heap_commit, self.loader_flags, self.number_of_rva_and_sizes = \
                struct.unpack('H2B5I6H6I2H8I', self.optional_header[:96])

        except struct.error as e:
            print(f"Error unpacking optional header: {e}")

    def _parse_sections(self, f):
        try:
            for i in range(self.number_of_sections):
                # Each section header takes exactly 40 bytes
                section = f.read(40)
                name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, \
                    pointer_to_relocations, pointer_to_line_numbers, number_of_relocations, \
                    number_of_line_numbers, characteristics = struct.unpack('8s6I2HI', section)
                self.sections.append({
                    'Name': name.decode(errors='ignore').strip(),
                    'VirtualAddress': virtual_address,
                    'VirtualSize': virtual_size,
                    'RawSize': size_of_raw_data,
                    'Characteristics': characteristics
                })
        except struct.error as e:
            print(f"Error unpacking section header: {e}")

    # Spent a ton of time implementing this without a library, I give up
    def demangle(self, name):
        try:
            return cxxfilt.demangle(name)
        except:
            return name

    def display_headers(self, show_optional=False, show_directories=False, show_sections=False, show_imports=False,
                        show_exports=False):
        try:
            print(f"File: {self.file_path}")
            print(f"Magic: {self.e_magic}")

            print("\nPE Header:")
            print(f"  Number of Sections: {self.number_of_sections}")
            print(f"  Size of Optional Header: {self.size_of_optional_header}")
            print(f"  Characteristics: {hex(self.characteristics)}")
            print(f"  Time Date Stamp: {self.time_date_stamp}")

            if show_optional:
                # print("\nOptional Header:")
                # for i, field in enumerate(self.optional_header_fields):
                #     print(f"  Field {i}: {field}")
                print("\nOptional Header:")
                print(f"  Address of Entry Point: {hex(self.address_of_entry_point)}")
                print(f"  Image Base: {hex(self.image_base)}")
                print(f"  Section Alignment: {self.section_alignment}")
                print(f"  File Alignment: {self.file_alignment}")
                print(f"  Size of Image: {self.size_of_image}")
                print(f"  Size of Headers: {self.size_of_headers}")
                print(f"  Subsystem: {self.subsystem}")
                print(f"  Dll Characteristics: {hex(self.dll_characteristics)}")
                print(f"  Number of Rva and Sizes: {self.number_of_rva_and_sizes}")

            if show_directories:
                print("\nData Directories:")

                # first 96 bytes have already been unpacked earlier for other fields
                # number_of_rva_and_sizes contains the number of data directories
                # each data directory is 8 bytes (4 bytes for virtual address and 4 bytes for size)
                data_directories = self.optional_header[96:96 + 8 * self.number_of_rva_and_sizes]
                for i in range(self.number_of_rva_and_sizes):
                    virtual_address, size = struct.unpack_from('II', data_directories, i * 8)
                    print(f"  Directory {i}: VirtualAddress: {hex(virtual_address)}, Size: {size}")

            if show_sections:
                print("\nSections:")
                for section in self.sections:
                    print(f"  Name: {section['Name']}")
                    print(f"  Virtual Address: {hex(section['VirtualAddress'])}")
                    print(f"  Virtual Size: {section['VirtualSize']}")
                    print(f"  Raw Size: {section['RawSize']}")
                    print(f"  Characteristics: {hex(section['Characteristics'])}")
                    print("  -------------------------")

            # In the next two methods I use pefile because I can't seem to read it manually... Maybe I'm missing something?
            pe = PE(self.file_path)

            if show_imports:
                print("\nImport Table:")
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        print(f" {entry.dll.decode('utf-8')}")
                        for imp in entry.imports:
                            name = imp.name.decode('utf-8') if imp.name else f'ordinal ({imp.ordinal})'
                            demangled_name = self.demangle(name) if imp.name else name
                            print(f"  {demangled_name} ({imp.ordinal})")
                else:
                    print(" None")

            if show_exports:
                print("\nExport Table:")
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        name = export.name.decode('utf-8') if export.name else f'ordinal ({export.ordinal})'
                        demangled_name = self.demangle(name) if export.name else name
                        print(f"  {demangled_name} ({export.ordinal})")
                else:
                    print(" None")

        except Exception as e:
            print(f"An error occurred while displaying headers: {e}")
