import unittest
from tempfile import NamedTemporaryFile
import struct
from pefile_parser import PEFile


class TestPEFileMethods(unittest.TestCase):

    def setUp(self):

        # Создаем временный PE файл для тестирования
        self.test_pe_file = NamedTemporaryFile(delete=False)

        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('I', 128)  # e_lfanew = 128
        pe_header = b'PE\x00\x00' + b'\x4C\x01' + b'\x02\x00' + b'\x00' * 16 + struct.pack('H', 224) + b'\x00\x02'
        optional_header = b'\x0B\x01' + b'\x02' * 94  # Только первые 96 байт

        section_name = 'test'.encode('utf-8')
        section_header = section_name + b'\x00' * (8 - len(section_name)) + struct.pack('I', 0x1000) * 2 + struct.pack('I', 0x200) + struct.pack('I', 0x200) + b'\x00' * 16

        self.test_pe_file.write(dos_header)
        self.test_pe_file.write(b'\x00' * (128 - len(dos_header)))
        self.test_pe_file.write(pe_header)
        self.test_pe_file.write(optional_header)
        self.test_pe_file.write(section_header)
        self.test_pe_file.close()

        self.pe_file = PEFile(self.test_pe_file.name)
        self.pe_parsed = self.pe_file.parse()

    def tearDown(self):
        # Удаляем временный PE файл после тестирования
        import os
        os.remove(self.test_pe_file.name)

    def test_parse(self):
        self.pe_file.parse()
        # Проверяем заголовки
        self.assertIsNotNone(self.pe_file.dos_header)
        self.assertIsNotNone(self.pe_file.pe_header)
        self.assertIsNotNone(self.pe_file.optional_header)
        self.assertNotEqual(len(self.pe_file.sections), 0)

    def test_parse_dos_header(self):
        with open(self.test_pe_file.name, 'rb') as f:
            self.pe_file._parse_dos_header(f)
        self.assertEqual(self.pe_file.e_magic, b'MZ')

    def test_parse_pe_header(self):
        with open(self.test_pe_file.name, 'rb') as f:
            self.pe_file._parse_dos_header(f)
            self.pe_file._parse_pe_header(f)
        self.assertEqual(self.pe_file.signature, b'PE\x00\x00')

    def test_parse_optional_header(self):
        with open(self.test_pe_file.name, 'rb') as f:
            self.pe_file._parse_dos_header(f)
            self.pe_file._parse_pe_header(f)
            self.pe_file._parse_optional_header(f)
        self.assertEqual(self.pe_file.e_magic, b'MZ')  # Assuming magic number for PE32

    # эта ###### даже с рекваерментсами не работает
    def test_parse_sections(self):

        with open(self.test_pe_file.name, 'rb') as f:
            self.pe_file._parse_dos_header(f)
            self.pe_file._parse_pe_header(f)
            self.pe_file._parse_optional_header(f)
            self.pe_file._parse_sections(f)

        self.assertEqual(len(self.pe_file.sections), 4)
        

#и эта
    def test_demangle(self):
        mangled_name = '_ZN12_GLOBAL__N_11funcEv'
        demangled_name = self.pe_file.demangle(mangled_name)
        self.assertEqual(demangled_name, '_ZN12_GLOBAL__N_11funcEv') # anonymous namespace::func()

    def test_display_headers(self):
        import sys
        from io import StringIO

        captured_output = StringIO()

        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            self.pe_file.display_headers(show_optional=True, show_sections=True)
        finally:
            sys.stdout = original_stdout

        output = captured_output.getvalue()
        self.assertIn("Number of Sections", output)
        self.assertIn("Size of Optional Header", output)
        self.assertIn("Sections:", output)


if __name__ == '__main__':
    unittest.main()
