import argparse
import pefile_parser as pp


def main():
    try:
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
        parser.add_argument(
            "-i",
            "--imports",
            action="store_true",
            help="display import table information"
        )
        parser.add_argument(
            "-e",
            "--exports",
            action="store_true",
            help="display export table information"
        )
        args = parser.parse_args()

        try:
            pe_file = pp.PEFile(args.file)
            pe_file.parse()
            pe_file.display_headers(
                show_optional=args.optional,
                show_directories=args.directories,
                show_sections=args.sections,
                show_imports=args.imports,
                show_exports=args.exports
            )
        except FileNotFoundError:
            print(f"File '{args.file}' was not found. File parse is not possible")
        except Exception as e:
            print(f"An error occurred while processing the PE file: {e}")

    except argparse.ArgumentError as e:
        print(f"Argument parsing error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
