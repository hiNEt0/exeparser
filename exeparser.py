import argparse
import pefile_parser as pp


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

    pe_file = pp.PEFile(args.file)
    pe_file.parse()
    pe_file.display_headers(
        show_optional=args.optional,
        show_directories=args.directories,
        show_sections=args.sections
    )


if __name__ == "__main__":
    main()
