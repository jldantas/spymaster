import os.path
import sys
import argparse
import logging
import time
import csv
import json
import time
import multiprocessing as mp
import shutil
from itertools import chain as _chain

import libmft.api
from libmft.flagsandtypes import AttrTypes, FileInfoFlags, MftUsageFlags
from libmft.exceptions import DataStreamError

import dateutil #https://dateutil.readthedocs.io/en/stable/index.html
import dateutil.zoneinfo

_MOD_LOGGER = logging.getLogger(__name__)

_CSV_COLUMN_ORDER = ["entry_n", "is_deleted", "is_directory", "is_ads", "path",
                "size", "alloc_size",
                "std_created", "std_changed", "std_mft_change", "std_accessed",
                "fn_created", "fn_changed", "fn_mft_change", "fn_accessed",
                "readonly", "hidden", "system", "encrypted"]

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
def output_csv(mft, args, temp_filename, start_point, end_point):
    global _CSV_COLUMN_ORDER

    #TODO windows messing things? test on linux
    #TODO https://stackoverflow.com/questions/16271236/python-3-3-csv-writer-writes-extra-blank-rows
    with open(temp_filename, "w", encoding="utf-8", newline="") as csv_output:
        writer = csv.DictWriter(csv_output, fieldnames=_CSV_COLUMN_ORDER)

        i = 0
        buf_size = 8192
        buffer = [None] * buf_size
        for data in get_mft_entry_info(mft, args, start_point, end_point):
            print(data)
            buffer[i] = data
            i += 1
            if i == buf_size:
                writer.writerows(buffer)
                i = 0
        if buffer:
            writer.writerows(buffer)

def output_json(mft, args, temp_filename, start_point, end_point):
    with open(temp_filename, "w") as json_output:
        for data in get_mft_entry_info(mft, args, start_point, end_point):
            json.dump(data, json_output)

def output_bodyfile(mft, temp_filename, start_point, end_point):
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

    with open(args.output, "w", encoding="utf-8") as csv_output:
        writer = csv.writer(csv_output, dialect=BodyFileDialect)

        for data in get_mft_entry_info(mft, args, start_point, end_point):
            temp = [0, data["path"], data["entry_n"], 0, 0, 0, data["size"]]
            if use_fn_info:
                dates = [convert_time(data["fn_accessed"]),
                         convert_time(data["fn_changed"]),
                         convert_time(data["fn_mft_change"]),
                         convert_time(data["fn_created"])]
            else:
                dates = [convert_time(data["std_accessed"]),
                         convert_time(data["std_changed"]),
                         convert_time(data["std_mft_change"]),
                         convert_time(data["std_created"])]

            writer.writerow(_chain(temp, dates))


#------------------------------------------------------------------------------
# PROCESSING SECTION
#------------------------------------------------------------------------------

def build_output_dict(mft, entry, std_info, fn, ds, timezone, time_format="%Y-%m-%d %H:%M:%S"):
    data = {}
    data["is_deleted"] = entry.is_deleted
    data["is_directory"] = entry.is_directory
    data["entry_n"] = entry.header.mft_record

    if std_info is not None:
        std_info_content = std_info.content
        std_info_ti = std_info_content.timestamps.astimezone(timezone)
        data["std_created"] = std_info_ti.created.strftime(time_format)
        data["std_changed"] = std_info_ti.changed.strftime(time_format)
        data["std_mft_change"] = std_info_ti.mft_changed.strftime(time_format)
        data["std_accessed"] = std_info_ti.accessed.strftime(time_format)
    else:
        data["std_created"] = data["std_changed"] = data["std_mft_change"] = \
            data["std_accessed"] = ""

    if fn is not None:
        fn_content = fn.content
        fn_ti = fn_content.timestamps.astimezone(timezone)
        data["fn_created"] = fn_ti.created.strftime(time_format)
        data["fn_changed"] = fn_ti.changed.strftime(time_format)
        data["fn_mft_change"] = fn_ti.mft_changed.strftime(time_format)
        data["fn_accessed"] = fn_ti.accessed.strftime(time_format)
    else:
        data["fn_created"] = data["fn_changed"] = data["fn_mft_change"] = \
            data["fn_accessed"] = ""

    if fn is not None:
        if ds is None or ds.name is None:
            orphan, data["path"] = mft.get_full_path(fn)
            data["is_ads"] = False
        else:
            orphan, data["path"] = mft.get_full_path(fn)
            data["path"] = ":".join((data["path"], ds.name))
            data["is_ads"] = True
    else:
        orphan = False
        data["path"] = ""
        data["is_ads"] = False

    if orphan:
        data["path"] = "__ORPHAN__" + "\\" + data["path"]

    if ds is not None:
        data["size"] = ds.size
        data["alloc_size"] = ds.alloc_size
    else:
        data["size"] = data["alloc_size"] = "0"

    data["readonly"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.READ_ONLY else False
    data["hidden"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.HIDDEN else False
    data["system"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.SYSTEM else False
    data["encrypted"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.ENCRYPTED else False

    return data

def get_mft_entry_info(mft, args, start_point, end_point):
    for entry in mft.splice_generator(start_point, end_point):
        #sometimes entries have no attributes and are marked as deleted, there is no information there
        if not entry.attrs and entry.is_deleted:
            continue
        #other times, we might have a partial entry (entry that has been deleted,
        #but occupied more than one entry) and not have the basic attribute information
        #like STANDARD_INFORMATION or FILENAME, in these cases, ignore as well
        if not entry.is_deleted and not entry.has_attribute(AttrTypes.STANDARD_INFORMATION):
            continue

        std_info = entry.get_attributes(AttrTypes.STANDARD_INFORMATION)[0]
        fn_attrs = entry.get_unique_filename_attrs()
        main_fn = entry.get_main_filename_attr()
        ds_names = entry.get_datastream_names()
        main_ds = None

        if not fn_attrs:
            fn_attrs = [None]
            main_fn = None

        if ds_names is not None:
            for ds_name in ds_names:
                yield build_output_dict(mft, entry, std_info, main_fn, entry.get_datastream(ds_name), args.timezone, args.time_format)
            if None in ds_names:
                main_ds = entry.get_datastream()
        else:
            yield build_output_dict(mft, entry, std_info, main_fn, main_ds, args.timezone, args.time_format)

        if main_fn:
            for fn in fn_attrs:
                if fn.content.parent_ref != main_fn.content.parent_ref: #if it is the same file name (which was printed)
                    yield build_output_dict(mft, entry, std_info, fn, main_ds, args.timezone, args.time_format)


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
    parser.add_argument("-c", "--cores", dest="n_cores", metavar="<cores>", type=int, default=0, help="Control how many cores will be used for processing. 0 will try to use as many cores as possible, 1 disables multiprocessing.")
    parser.add_argument("-t", "--timezone", dest="timezone", metavar="<timezone name>", default="UTC", help="Convert all the times used by the script to the provided timezone. Use '--list-tz' to check available timezones. Default is UTC.")
    parser.add_argument("--tf", dest="time_format", metavar="<time format>", default="%Y-%m-%d %H:%M:%S", help="How the time information is printed. Use the same format as in the strftime function.")
    parser.add_argument("--list-tz", dest="show_tz", action="store_true", help="Prints a list of all available timezones.")
    parser.add_argument("-o", "--output", dest="output", metavar="<output file>", required=False, help="The filename and path where the resulting file will be saved.")
    parser.add_argument("-i", "--input", dest="input", metavar="<input file>", required=False, help="The MFT file to be processed.")
    parser.add_argument("-v", "--verbose", dest="verbose", action="count", default=0, help="Enables verbose/debug mode.")

    args = parser.parse_args()

    #TODO mutually exclude -f and -d

    #can only use the --fn option with the bodyfile format
    if args.use_fn and args.format != "bodyfile":
        parser.error("Argument '--fn' can only be used with 'bodyfile' format.")

    if not args.show_tz and (args.input is None or args.output is None):
        parser.error("the following arguments are required: -o/--output, -i/--input")

    return args

def print_timezones():
    """List all the available timezones.

    Print a three column message with all the timezones available to the
    script.
    """
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

#------------------------------------------------------------------------------
# PARALLEL SECTION
#------------------------------------------------------------------------------
def generate_name_file(id, output_name):
    #TODO use a better algorithm to get the names
    v = 1
    while True:
        temp_name = (v * str(id)) + output_name
        if not os.path.exists(temp_name):
            return temp_name
        else:
            v += 1

def worker(id, temp_output_file, args, mft_config):

    with open(args.input, "rb") as input_file:
        mft = libmft.api.MFT(input_file, mft_config)
        #calculate the offset that this process is going to work on
        total, remainder = divmod(mft.total_amount_entries, args.n_cores)
        start = id * total
        end = (id + 1) * total if id != args.n_cores - 1 else ((id + 1) * total) + remainder
        _MOD_LOGGER.debug("Proc %d - From %d to %d.", id, start, end)

        if args.format == "csv":
            output_csv(mft, args, temp_output_file, start, end)
        elif args.format == "json":
            output_json(mft, args, temp_output_file, start, end)
        # elif args.format == "bodyfile":
        #     output_bodyfile(mft, args)

    return temp_output_file

def merge_files(file_list, args):
    global _CSV_COLUMN_ORDER

    if args.format == "csv":
        output_file = open(args.output, "w", encoding="utf-8", newline="")
        writer = csv.DictWriter(output_file, fieldnames=_CSV_COLUMN_ORDER)
        writer.writeheader()
    elif args.format == "json":
        output_file = open(args.output, "w")

    #TODO try/except block
    for file in file_list:
        with open(file, "r", encoding="utf-8") as input_file:
            shutil.copyfileobj(input_file, output_file)

    output_file.close()



def remove_temp_files(file_list):
    _MOD_LOGGER.info(f"Removing intermediate files...")
    for file in file_list:
        if os.path.exists(file):
            _MOD_LOGGER.debug("Removing file %s...", file)
            os.remove(file)

def main():
    _MOD_LOGGER.addHandler(logging.StreamHandler(sys.stderr))
    args = get_arguments()

    if args.verbose >= 1:
        _MOD_LOGGER.setLevel(level=logging.DEBUG)
    else:
        _MOD_LOGGER.setLevel(level=logging.INFO)

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

    if args.n_cores == 0:
        #never use all the cores, leave one for the others
        args.n_cores = mp.cpu_count() - 1

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

    _MOD_LOGGER.debug("Provided options: %s", args)


    #TODO some kind of progress bar
    #TODO dump all resident files
    #TODO some kind of "anomaly" detection?
    #TODO symbolic links and junction points

    start_time = time.time()
    if args.dump_entry is None:
        if args.n_cores == 1:
            worker(0, args.output, args, mft_config)
        else:
            process_args = [(i, generate_name_file(i, args.output), args, mft_config) for i in range(args.n_cores)]
            #TODO there is a potential race condition here, fix
            # if two are started at the same time for a mft file, it is possible that
            # both process try to generate the same name before the creation of the
            # file. If this happens, you have two processes writing in the same file,
            # hence, race condition.
            file_list = [p_arg[1] for p_arg in process_args]
            with mp.Pool(args.n_cores) as pool:
                pool.starmap(worker, process_args)
                merge_files(file_list, args)
            remove_temp_files(file_list)
    else:
        _MOD_LOGGER.info(f"Dumping entry '{args.dump_entry}' to file '{args.output}'.")
        try:
            dump_resident_file(mft, args.output, args.dump_entry)
        except SpymasterError as e:
            _MOD_LOGGER.error(str(e))

    end_time = time.time()
    print(end_time - start_time)


if __name__ == '__main__':
    main()
