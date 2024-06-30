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
            self.pe_headers = list(struct.unpack('4s2H3I2H', self.pe_header))

        except struct.error as e:
            print(f"Error unpacking PE header: {e}")

    def _parse_optional_header(self, f):
        try:
            self.optional_header = f.read(self.pe_headers[6])
            # B - 8-bit unsigned int (unsigned char)
            self.optional_headers = list(struct.unpack('H2B5I6H6I2H8I', self.optional_header[:96]))

        except struct.error as e:
            print(f"Error unpacking optional header: {e}")

    def _parse_sections(self, f):
        try:
            for i in range(self.pe_headers[2]):
                # Each section header takes exactly 40 bytes
                section = f.read(40)
                section_params = list(struct.unpack('8s6I2HI', section))
                self.sections.append({
                    'Name': section_params[0].decode(errors='ignore').strip(),
                    'VirtualAddress': section_params[2],
                    'VirtualSize': section_params[1],
                    'RawSize': section_params[3],
                    'Characteristics': section_params[9]
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
            print(f"  Number of Sections: {self.pe_headers[2]}")
            print(f"  Size of Optional Header: {self.pe_headers[6]}")
            print(f"  Characteristics: {hex(self.pe_headers[7])}")
            print(f"  Time Date Stamp: {self.pe_headers[3]}")

            if show_optional:
                print("\nOptional Header:")
                print(f"  Address of Entry Point: {hex(self.optional_headers[6])}")
                print(f"  Image Base: {hex(self.optional_headers[9])}")
                print(f"  Section Alignment: {self.optional_headers[10]}")
                print(f"  File Alignment: {self.optional_headers[11]}")
                print(f"  Size of Image: {self.optional_headers[19]}")
                print(f"  Size of Headers: {self.optional_headers[20]}")
                print(f"  Subsystem: {self.optional_headers[22]}")
                print(f"  Dll Characteristics: {hex(self.optional_headers[23])}")
                print(f"  Number of Rva and Sizes: {self.optional_headers[29]}")

            if show_directories:
                print("\nData Directories:")
                # first 96 bytes have already been unpacked earlier for other fields
                # number_of_rva_and_sizes contains the number of data directories
                # each data directory is 8 bytes (4 bytes for virtual address and 4 bytes for size)
                data_directories = self.optional_header[96:96 + 8 * self.optional_headers[29]]
                for i in range(self.optional_headers[29]):
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
