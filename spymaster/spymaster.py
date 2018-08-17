import os.path
import sys
import argparse
import logging
import time
import csv
import multiprocessing as mp
import shutil
from itertools import chain as _chain
from json import dump as _json_dump

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

#------------------------------------------------------------------------------
# OUTPUT SECTION
#------------------------------------------------------------------------------
class OutputCSV():
    """Controls file output when the csv format is selected.
    """
    def __init__(self, filename, args):
        self.filename = filename
        self.fp = None
        self.writer = None
        self.time_format = args.time_format

    def _adjust_data(self, single_data):
        if single_data["std_created"]:
            single_data["std_created"] = single_data["std_created"].strftime(self.time_format)
            single_data["std_changed"] = single_data["std_changed"].strftime(self.time_format)
            single_data["std_mft_change"] = single_data["std_mft_change"].strftime(self.time_format)
            single_data["std_accessed"] = single_data["std_accessed"].strftime(self.time_format)
        if single_data["fn_created"]:
            single_data["fn_created"] = single_data["fn_created"].strftime(self.time_format)
            single_data["fn_changed"] = single_data["fn_changed"].strftime(self.time_format)
            single_data["fn_mft_change"] = single_data["fn_mft_change"].strftime(self.time_format)
            single_data["fn_accessed"] = single_data["fn_accessed"].strftime(self.time_format)

    def write_data(self, data):
        self._adjust_data(data)
        self.writer.writerows(self._buffer)

    def execute_pre_merge(self):
        self.writer.writeheader()

    def __enter__(self):
        self.fp = open(self.filename, "w", encoding="utf-8", newline="")
        self.writer = csv.DictWriter(self.fp, fieldnames=_CSV_COLUMN_ORDER)

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.writer = None
        self.fp.close()

class OutputJSON():
    """Controls file output when the json format is selected.
    """
    def __init__(self, filename, args):
        self.filename = filename
        self.fp = None
        self.time_format = args.time_format

    def _adjust_data(self, single_data):
        if single_data["std_created"]:
            single_data["std_created"] = single_data["std_created"].strftime(self.time_format)
            single_data["std_changed"] = single_data["std_changed"].strftime(self.time_format)
            single_data["std_mft_change"] = single_data["std_mft_change"].strftime(self.time_format)
            single_data["std_accessed"] = single_data["std_accessed"].strftime(self.time_format)
        if single_data["fn_created"]:
            single_data["fn_created"] = single_data["fn_created"].strftime(self.time_format)
            single_data["fn_changed"] = single_data["fn_changed"].strftime(self.time_format)
            single_data["fn_mft_change"] = single_data["fn_mft_change"].strftime(self.time_format)
            single_data["fn_accessed"] = single_data["fn_accessed"].strftime(self.time_format)

    def write_data(self, data):
        self._adjust_data(data)
        _json_dump(data, self.fp)

    def execute_pre_merge(self):
        pass

    def __enter__(self):
        self.fp = open(self.filename, "w")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fp.close()

class BodyFileDialect(csv.Dialect):
    """To write the bodyfile, we cheat. By defining a new csv dialect, we can
    offload all the file writing to the csv module.
    """
    delimiter = "|"
    doublequote = False
    lineterminator = "\n"
    quotechar = ""
    quoting = csv.QUOTE_NONE

class OutputBodyFile():
    """Controls file output when the bodyfile format is selected.

    Outputs in TSK 3.0+ bodyfile format according to the following format:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    found at: https://wiki.sleuthkit.org/index.php?title=Body_file
    atime = access time
    mtime = changed time
    ctime = mft changed time
    crtime = createad time
    """

    def __init__(self, filename, args):
        self.filename = filename
        self.fp = None
        self.writer = None
        self.use_fn = args.use_fn

    def _get_converted_time(self, data):
        def convert_time(value):
            '''An unix timestamp exists only after 1970, if we need to convert something
            that is before that time, we get an error. This internal function avoids it.
            '''
            return int(value.timestamp()) if value.year >= 1970 else ""

        if self.use_fn:
            if data["fn_created"]:
                dates = [convert_time(data["fn_accessed"]),
                         convert_time(data["fn_changed"]),
                         convert_time(data["fn_mft_change"]),
                         convert_time(data["fn_created"])]
            else:
                dates = ["", "", "", ""]
        else:
            if data["std_created"]:
                dates = [convert_time(data["std_accessed"]),
                         convert_time(data["std_changed"]),
                         convert_time(data["std_mft_change"]),
                         convert_time(data["std_created"])]
            else:
                dates = ["", "", "", ""]

        return dates

    def write_data(self, data):
        temp = [0, data["path"], data["entry_n"], 0, 0, 0, data["size"]]
        dates = self._get_converted_time(data)
        self.writer.writerow(_chain(temp, dates))

    def execute_pre_merge(self):
        pass

    def __enter__(self):
        self.fp = open(self.filename, "w", encoding="utf-8")
        self.writer = csv.writer(self.fp, dialect=BodyFileDialect)

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.writer = None
        self.fp.close()

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
# PROCESSING SECTION
#------------------------------------------------------------------------------
def build_data_output(mft, entry, std_info, fn, ds, args):
    data = {}
    #get entry related information
    data["is_deleted"] = entry.is_deleted
    data["is_directory"] = entry.is_directory
    data["entry_n"] = entry.header.mft_record

    #get STANDARD_INFORMATION timestamps
    if std_info is not None:
        std_info_content = std_info.content
        std_info_ti = std_info_content.timestamps.astimezone(args.timezone)
        data["std_created"] = std_info_ti.created
        data["std_changed"] = std_info_ti.changed
        data["std_mft_change"] = std_info_ti.mft_changed
        data["std_accessed"] = std_info_ti.accessed
        #get STANDARD_INFORMATION related info
        data["readonly"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.READ_ONLY else False
        data["hidden"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.HIDDEN else False
        data["system"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.SYSTEM else False
        data["encrypted"] = True if std_info_content.flags & libmft.flagsandtypes.FileInfoFlags.ENCRYPTED else False
    else:
        data["std_created"] = data["std_changed"] = data["std_mft_change"] = \
            data["std_accessed"] = data["readonly"] = data["hidden"] = data["system"] = \
            data["encrypted"] = ""
    #get FILENAME timestamps
    if fn is not None:
        fn_content = fn.content
        fn_ti = fn_content.timestamps.astimezone(args.timezone)
        data["fn_created"] = fn_ti.created
        data["fn_changed"] = fn_ti.changed
        data["fn_mft_change"] = fn_ti.mft_changed
        data["fn_accessed"] = fn_ti.accessed
        #get the full path
        orphan, data["path"] = mft.get_full_path(fn)
        #fix path if it is ads
        if ds is None or ds.name is None:
            data["is_ads"] = False
        else:
            data["path"] = ":".join((data["path"], ds.name))
            data["is_ads"] = True
    else:
        data["fn_created"] = data["fn_changed"] = data["fn_mft_change"] = \
            data["fn_accessed"] = ""
        #if we have no filename attr, path cant be calculated
        orphan = False
        data["path"] = ""
        data["is_ads"] = False

    #if we have an orphan path, let's make it clear
    if orphan:
        data["path"] = "\\".join(("__ORPHAN__", data["path"]))
    #get size from the datastream
    if ds is not None:
        data["size"] = ds.size
        data["alloc_size"] = ds.alloc_size
    else:
        data["size"] = data["alloc_size"] = "0"

    return data


def iter_mft_data(mft, args, start, end):
    for entry in mft.splice_generator(start, end):
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
        main_ds = entry.get_datastream()
        #if the entry has no FILENAME attributes, build the default
        if not fn_attrs:
            fn_attrs = [None]
            main_fn = None
        # with the main filename found, let's find the ads and return
        if ds_names is not None:
            for ds_name in ds_names:
                yield build_data_output(mft, entry, std_info, main_fn, entry.get_datastream(ds_name), args)
        else:
            yield build_data_output(mft, entry, std_info, main_fn, main_ds, args)
        #iterate over the hardlinks
        if main_fn:
            for fn in fn_attrs:
                if fn.content.parent_ref != main_fn.content.parent_ref: #if it is the same file name (which was printed)
                    yield build_data_output(mft, entry, std_info, fn, main_ds, args)

def worker(id, output_file, args, mft_config):

    with open(args.input, "rb") as input_file:
        mft = libmft.api.MFT(input_file, mft_config)
        #calculate the offset that this process is going to work on
        total, remainder = divmod(mft.total_amount_entries, args.n_cores)
        start = id * total
        end = (id + 1) * total if id != args.n_cores - 1 else ((id + 1) * total) + remainder
        _MOD_LOGGER.debug("Proc %d - From %d to %d.", id, start, end)

        #open the correct output and spit things out :D
        with args.output_class(output_file, args) as output:
            for data in iter_mft_data(mft, args, start, end):
                output.write_data(data)

    return output_file

#------------------------------------------------------------------------------
# MAIN SECTION
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

def merge_files(file_list, args):
    with args.output_class(args.output, args) as output_file:
        output_file.execute_pre_merge()
        for file in file_list:
            with open(file, "r", encoding="utf-8") as input_file:
                shutil.copyfileobj(input_file, output_file.fp)

def remove_temp_files(file_list):
    _MOD_LOGGER.info(f"Removing intermediate files...")
    for file in file_list:
        if os.path.exists(file):
            _MOD_LOGGER.debug("Removing file %s...", file)
            os.remove(file)

def process_program_args(args):
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

    if args.n_cores == 0:
        #never use all the cores, leave one for the others
        args.n_cores = mp.cpu_count() - 1

    if args.format == "csv":
        args.output_class = OutputCSV
    elif args.format == "json":
        args.output_class = OutputJSON
    elif args.format == "bodyfile":
        args.output_class = OutputBodyFile

def main():
    _MOD_LOGGER.addHandler(logging.StreamHandler(sys.stderr))
    args = get_arguments()

    process_program_args(args)

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

    if os.path.exists(args.output):
        _MOD_LOGGER.warning(f"The output file '{args.output}' exists and will be overwritten. You have 5 seconds to cancel the execution (CTRL+C).")
        time.sleep(5)

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
    _MOD_LOGGER.info(f"Execution time: {end_time - start_time}")


if __name__ == '__main__':
    main()
