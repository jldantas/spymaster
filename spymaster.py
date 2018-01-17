import argparse, logging
import os.path, sys
import csv, json
import time
from itertools import chain as _chain

import libmft.api
from libmft.flagsandtypes import AttrTypes, FileInfoFlags, MftUsageFlags
from libmft.exceptions import DataStreamError

import dateutil #https://dateutil.readthedocs.io/en/stable/index.html
import dateutil.zoneinfo

_MOD_LOGGER = logging.getLogger(__name__)

class SpymasterError(Exception):
    """ 'Generic' error class for the script"""
    pass

class BodyFileDialect(csv.Dialect):
    """To write the bodyfile, we cheat. By defining a new csv dialect, we can
    offload all the file writing to the csv module.
    """
    delimiter = "|"
    doublequote = False
    lineterminator = "\n"
    quotechar = ""
    quoting = csv.QUOTE_NONE

#------------------------------------------------------------------------------
# OUTPUT SECTION
#------------------------------------------------------------------------------
def output_csv(mft, args):
    column_order = ["entry_n", "is_deleted", "is_directory", "is_ads", "path",
                    "size", "alloc_size",
                    "std_created", "std_changed", "std_mft_change", "std_accessed",
                    "fn_created", "fn_changed", "fn_mft_change", "fn_accessed",
                    "readonly", "hidden", "system", "encrypted"]

    #TODO windows messing things? test on linux
    #TODO https://stackoverflow.com/questions/16271236/python-3-3-csv-writer-writes-extra-blank-rows
    with open(args.output, "w", encoding="utf-8", newline="") as csv_output:
        writer = csv.DictWriter(csv_output, fieldnames=column_order)
        writer.writeheader()

        for data in get_mft_entry_info(mft, args):
            #format_time(data, timezone)
            writer.writerow(data)

def output_json(mft, args):
    with open(args.output, "w") as json_output:
        for data in get_mft_entry_info(mft, args):
            data["std_created"] = data["std_created"].isoformat()
            data["std_changed"] = data["std_changed"].isoformat()
            data["std_mft_change"] = data["std_mft_change"].isoformat()
            data["std_accessed"] = data["std_accessed"].isoformat()
            data["fn_created"] = data["fn_created"].isoformat()
            data["fn_changed"] = data["fn_changed"].isoformat()
            data["fn_mft_change"] = data["fn_mft_change"].isoformat()
            data["fn_accessed"] =  data["fn_accessed"].isoformat()

            json.dump(data, json_output)

def output_bodyfile(mft, args):
    """Outputs in TSK 3.0+ bodyfile format according to the following format:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    found at: https://wiki.sleuthkit.org/index.php?title=Body_file
    atime = access time
    mtime = changed time
    ctime = mft changed time
    crtime = createad time
    """
    def convert_time(value):
        '''An unix timestamp exists only after 1970, if we need to convert something
        that is before that time, we get an error. This internal function avoids it.
        '''
        return int(value.timestamp()) if value.year >= 1970 else 0

    #TODO windows messing things? test on linux
    #TODO https://stackoverflow.com/questions/16271236/python-3-3-csv-writer-writes-extra-blank-rows
    with open(args.output, "w", encoding="utf-8") as csv_output:
        writer = csv.writer(csv_output, dialect=BodyFileDialect)

        for data in get_mft_entry_info(mft, args):
            temp = [0, data["path"], data["entry_n"], 0, 0, 0, data["size"]]
            if use_fn_info:
                dates = [convert_time(data["fn_accessed"]),
                         convert_time(data["fn_changed"]),
                         convert_time(data["fn_mft_change"]),
                         convert_time(data["fn_created"])]
            else:
                dates = [int(data["std_accessed"].timestamp()),
                         int(data["std_changed"].timestamp()),
                         int(data["std_mft_change"].timestamp()),
                         int(data["std_created"].timestamp())]

            writer.writerow(_chain(temp, dates))


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

def build_entry_info(mft, entry, std_info, fn_attr, ds, timezone):
    data = {}
    data["is_deleted"] = entry.is_deleted()
    data["is_directory"] = entry.is_directory()
    data["entry_n"] = entry.header.mft_record
    data["std_created"] = std_info.content.get_created_time().astimezone(timezone)
    data["std_changed"] = std_info.content.get_changed_time().astimezone(timezone)
    data["std_mft_change"] = std_info.content.get_mftchange_time().astimezone(timezone)
    data["std_accessed"] = std_info.content.get_accessed_time().astimezone(timezone)
    data["fn_created"] = fn_attr.content.get_created_time().astimezone(timezone)
    data["fn_changed"] = fn_attr.content.get_changed_time().astimezone(timezone)
    data["fn_mft_change"] = fn_attr.content.get_mftchange_time().astimezone(timezone)
    data["fn_accessed"] = fn_attr.content.get_accessed_time().astimezone(timezone)
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


def get_mft_entry_info(mft, args):
    default_stream = libmft.api.Datastream() #default empty stream
    fake_time = libmft.util.functions.convert_filetime(0) #default "0" time
    default_filename = libmft.api.Attribute(None, #deafult "empty" FileName attribute
        libmft.attrcontent.FileName((5, mft[5].header.seq_number,
            fake_time, fake_time, fake_time, fake_time,
            libmft.flagsandtypes.FileInfoFlags(0), -1, 0,
            libmft.flagsandtypes.NameType.POSIX, "__INVALID__")))

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
                yield build_entry_info(mft, entry, std_info, main_fn, entry.get_datastream(ds_name), args.timezone)
            if None in ds_names:
                main_ds = entry.get_datastream()
        else:
            yield build_entry_info(mft, entry, std_info, main_fn, default_stream, args.timezone)

        #TODO what happens in case of alternate data stream to a hardlink?
        for fn in fn_attrs:
            if fn.content.parent_ref != main_fn.content.parent_ref: #if it is the same file name (which was printed)
                yield build_entry_info(mft, entry, std_info, fn, main_ds, args.timezone)

def dump_resident_file(mft, output_file_path, entry_number):
    datastream = mft[entry_number].get_datastream()

    try:
        content = datastream.get_content()
        with open(output_file_path, "wb") as file_output:
            file_output.write(content)
    except DataStreamError as e:
        raise SpymasterError(f"Entry {entry_number} is not resident. Can't be dumped.")

'''
Input -> load -> correction -> output

output needs iterator/generator, arguments (output)
'''

#------------------------------------------------------------------------------
# CLI SECTION
#------------------------------------------------------------------------------
def get_arguments():
    '''Defines the arguments for the program and do all the necessary checks related
    to the options.
    '''
    parser = argparse.ArgumentParser(description="Parses a MFT file.")
    formats = ["csv", "json", "bodyfile"]

    parser.add_argument("-f", "--format", dest="format", metavar="<format>", default="csv", choices=formats, help="Format of the output file.")
    parser.add_argument("--fn", dest="use_fn", action="store_true", help="Specifies if the bodyfile format will use the FILE_NAME attribute for the dates. Valid only for bodyfile output.")
    parser.add_argument("-d", "--dump", dest="dump_entry", metavar="<entry number>", type=int, help="Dumps resident files from the MFT. Pass the entry number to dump the file. The name of the file needs to be specified using the '-o' option.")
    parser.add_argument("--disable-fixup", dest="disable_fixup", action="store_false", help="Disable the application of the fixup array. Should be used only when trying to get MFT entries from memory.")
    parser.add_argument("-t", "--timezone", dest="timezone", metavar="<timezone name>", default="UTC", help="Convert all the times used by the script to the provided timezone. Use '--list-tz' to check available timezones. Default is UTC.")
    parser.add_argument("--list-tz", dest="show_tz", action="store_true", help="Prints a list of all available timezones.")
    parser.add_argument("-o", "--output", dest="output", metavar="<output file>", required=False, help="The filename and path where the resulting file will be saved.")
    parser.add_argument("-i", "--input", dest="input", metavar="<input file>", required=False, help="The MFT file to be processed.")

    args = parser.parse_args()

    #TODO mutually exclude -f and -d

    #can only use the --fn option with the bodyfile format
    if args.use_fn and args.format != "bodyfile":
        parser.error("Argument '--fn' can only be used with 'bodyfile' format.")

    return args

def print_timezones():
    zone_names = list(dateutil.zoneinfo.get_zonefile_instance().zones)
    zone_names.sort()
    zone_iter = iter(zone_names)
    column_number = 3

    names_matrix = [[]]
    i = 0
    for name in zone_names:
        if i == column_number:
            names_matrix.append([])
            i = 0
        names_matrix[-1].append(name)
        i += 1
    #if the last line has less than number of columns, add the missing ones
    fix = column_number - len(names_matrix[-1])
    for i in range(fix):
        names_matrix[-1].append("-")

    for names in names_matrix:
        print("{0:32}{0:32}{0:32}".format(names[0], names[1], names[2]))


def main():
    _MOD_LOGGER.setLevel(level=logging.INFO)
    _MOD_LOGGER.addHandler(logging.StreamHandler(sys.stderr))
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
    mft_config.apply_fixup_array = args.disable_fixup

    if args.show_tz:
        print_timezones()
        sys.exit(0)
    args.timezone = dateutil.tz.gettz(args.timezone)

    if not os.path.isfile(args.input):
        _MOD_LOGGER.error(f"Path provided '{args.input}' is not a file or does not exists.")
        sys.exit(1)

    if os.path.exists(args.output):
        _MOD_LOGGER.warning(f"The output file '{args.output}' exists and will be overwritten. You have 5 seconds to cancel the execution (CTRL+C).")
        time.sleep(5)

    #TODO format time output
    #TODO some kind of progress bar
    #TODO dump all resident files
    #TODO some kind of "anomaly" detection?
    #TODO interactive mode?

    with open(args.input, "rb") as input_file:
        mft = libmft.api.MFT(input_file, mft_config)
        if args.dump_entry is None:
            if args.format == "csv":
                output_csv(mft, args)
            elif args.format == "json":
                output_json(mft, args)
            elif args.format == "bodyfile":
                output_bodyfile(mft, args)
            else:
                _MOD_LOGGER.error(f"An invalid format option was passed (bypassed -f check). SOMETHING WENT TO HELL.")
                sys.exit(2)
        else:
            _MOD_LOGGER.info(f"Dumping entry '{args.dump_entry}' to file '{args.output}'.")
            try:
                dump_resident_file(mft, args.output, args.dump_entry)
            except SpymasterError as e:
                _MOD_LOGGER.error(str(e))



if __name__ == '__main__':
    main()
