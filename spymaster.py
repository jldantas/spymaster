import argparse
import os.path
import sys

import libmft.api

def get_full_path(mft, fn_attr):
    names = [fn_attr.content.name]
    root_id = 5
    index, seq = fn_attr.content.parent_ref, fn_attr.content.parent_seq

    while index != root_id:
        try:
            entry = mft[index]

            if seq != entry.header.seq_number:
                names.append("_ORPHAN_")
                break
            else:
                parent_fn_attr = entry.get_main_filename_attr()
                index, seq = parent_fn_attr.content.parent_ref, parent_fn_attr.content.parent_seq
                names.append(parent_fn_attr.content.name)
        except ValueError as e:
            names.append("_ORPHAN_")
            break

    return "\\".join(reversed(names))

def get_arguments():
    parser = argparse.ArgumentParser(description="Parses a MFT file.")
    parser.add_argument("input_file_path", metavar="Input_File", help="The MFT file to be processed.")

    return parser.parse_args()

def main():
    args = get_arguments()

    mft_config = libmft.api.MFTConfig()
    mft_config.load_dataruns = False
    mft_config.load_object_id = False
    mft_config.load_sec_desc = False
    mft_config.load_idx_root = False
    mft_config.load_idx_alloc = False
    mft_config.load_bitmap = False
    mft_config.load_reparse = False
    mft_config.load_ea_info = False
    mft_config.load_ea = False
    mft_config.load_log_tool_str = False
    mft_config.load_attr_list = False

    if not os.path.isfile(args.input_file_path):
        print(f"Path provided '{args.input_file_path}' is not a file or does not exists.", file=sys.stderr)
        sys.exit(1)

    with open(args.input_file_path, "rb") as input_file:
        mft = libmft.api.MFT(input_file, mft_config)
        for i in mft:
            print(i)


if __name__ == '__main__':
    main()
