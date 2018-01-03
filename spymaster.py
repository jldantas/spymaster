import argparse
import os.path
import sys
import csv, json

import libmft.api
from libmft.flagsandtypes import AttrTypes, FileInfoFlags, MftUsageFlags

#------------------------------------------------------------------------------
# OUTPUT SECTION
#------------------------------------------------------------------------------
def output_csv(mft, output_file_path):
    column_order = ["entry_n", "is_deleted", "is_directory", "is_ads", "path",
                    "size", "alloc_size",
                    "std_created", "std_changed", "std_mft_change", "std_accessed",
                    "fn_created", "fn_changed", "fn_mft_change", "fn_accessed",
                    "readonly", "hidden", "system", "encrypted"]

    with open(output_file_path, "w") as csv_output:
        writer = csv.DictWriter(csv_output, fieldnames=column_order)
        writer.writeheader()

        for data in get_mft_entry_info(mft):
            writer.writerow(data)

def output_json(mft, output_file_path):
    with open(output_file_path, "w") as json_output:
        for data in get_mft_entry_info(mft):
            #TODO configure the output format
            data["std_created"] = data["std_created"].isoformat()
            data["std_changed"] = data["std_changed"].isoformat()
            data["std_mft_change"] = data["std_mft_change"].isoformat()
            data["std_accessed"] = data["std_accessed"].isoformat()
            data["fn_created"] = data["fn_created"].isoformat()
            data["fn_changed"] = data["fn_changed"].isoformat()
            data["fn_mft_change"] = data["fn_mft_change"].isoformat()
            data["fn_accessed"] =  data["fn_accessed"].isoformat()
            
            json.dump(data, json_output)

#------------------------------------------------------------------------------
# PROCESSING SECTION
#------------------------------------------------------------------------------
def get_full_path(mft, fn_attr):
    '''Returns the full path of a particular FILE_NAME attribute.
    It is necessary to consider FILE_NAME attrbutes instead of an entry because
    an entry can have multiple FILE_NAMEs which can be hardlinks (have a different
    parent).

    If the path is for a deleted entry, the root will be _ORPHAN_.
    '''
    names = [fn_attr.content.name] #the first is always the name itself
    root_id = 5 #root id is hardcoded
    #TODO see if we can figure out the root_id using only the mft
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

def build_entry_info(mft, entry, std_info, fn_attr, ds):
    data = {}
    data["is_deleted"] = entry.is_deleted()
    data["is_directory"] = entry.is_directory()
    data["entry_n"] = entry.header.mft_record
    data["std_created"] = std_info.content.get_created_time()
    data["std_changed"] = std_info.content.get_changed_time()
    data["std_mft_change"] = std_info.content.get_mftchange_time()
    data["std_accessed"] = std_info.content.get_accessed_time()
    data["fn_created"] = fn_attr.content.get_created_time()
    data["fn_changed"] = fn_attr.content.get_changed_time()
    data["fn_mft_change"] = fn_attr.content.get_mftchange_time()
    data["fn_accessed"] = fn_attr.content.get_accessed_time()
    if ds.name is None:
        data["path"] = get_full_path(mft, fn_attr)
        data["is_ads"] = False
    else:
        data["path"] = ":".join((get_full_path(mft, fn_attr), ds.name))
        data["is_ads"] = True
    data["size"] = ds.size
    data["alloc_size"] = ds.alloc_size

    data["readonly"] = True if std_info.content.flags & libmft.flagsandtypes.FileInfoFlags.READ_ONLY else False
    data["hidden"] = True if std_info.content.flags & libmft.flagsandtypes.FileInfoFlags.HIDDEN else False
    data["system"] = True if std_info.content.flags & libmft.flagsandtypes.FileInfoFlags.SYSTEM else False
    data["encrypted"] = True if std_info.content.flags & libmft.flagsandtypes.FileInfoFlags.ENCRYPTED else False

    return data


def get_mft_entry_info(mft):
    default_stream = libmft.api.Datastream() #default empty stream
    fake_time = libmft.util.functions.convert_filetime(0) #default "0" time
    default_filename = libmft.api.Attribute(None, #deafult "empty" FileName attribute
        libmft.attrcontent.FileName((5, mft[5].header.seq_number,
            fake_time, fake_time, fake_time, fake_time,
            libmft.flagsandtypes.FileInfoFlags(0), -1, 0,
            libmft.flagsandtypes.NameType.POSIX, "INVALID")))

    for entry in mft:
        #sometimes entries have no attributes and are marked as deleted, there is no information there
        if not entry.attrs and not entry.header.usage_flags:
            continue
        #other times, we might have a partial entry (entry that has been deleted,
        #but occupied more than one entry) and not have the basic attribute information
        #like STANDARD_INFORMATION or FILENAME, in these cases, ignore as well
        if not entry.header.usage_flags & libmft.flagsandtypes.MftUsageFlags.IN_USE and entry.get_attributes(AttrTypes.STANDARD_INFORMATION) is None:
            continue

        main_ds = default_stream
        std_info = entry.get_attributes(AttrTypes.STANDARD_INFORMATION)[0]
        fn_attrs = entry.get_unique_filename_attrs()
        main_fn = entry.get_main_filename_attr()
        #we might have a case where no filename attribute exists, so set to default
        if not fn_attrs:
            fn_attrs = [default_filename]
            main_fn = default_filename
        ds_names = entry.get_datastream_names()
        #we might have a case where no datastream exists, so set to default
        if ds_names is not None:
            for ds_name in ds_names:
                yield build_entry_info(mft, entry, std_info, main_fn, entry.get_datastream(ds_name))
            if None in ds_names:
                main_ds = entry.get_datastream()
        else:
            yield build_entry_info(mft, entry, std_info, main_fn, default_stream)

        #TODO what happens in case of alternate data stream to a hardlink?
        for fn in fn_attrs:
            if fn.content.parent_ref != main_fn.content.parent_ref: #if it is the same file name (which was printed)
                yield build_entry_info(mft, entry, std_info, fn, main_ds)




def get_arguments():
    parser = argparse.ArgumentParser(description="Parses a MFT file.")
    #TODO add output format CSV, JSON, bodyfile
    #TODO option to skip fixup array
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

    #TODO change timezone
    #TODO dump resident files
    #TODO interactive mode?

    with open(args.input_file_path, "rb") as input_file:
        mft = libmft.api.MFT(input_file, mft_config)
        output_json(mft, "teste.csv")


if __name__ == '__main__':
    main()
