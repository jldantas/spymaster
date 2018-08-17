# spymaster
Super PYthon Mft AnalySER

## Getting started

### Prerequisites

```
Python >= 3.6
libmft
python-dateutil
```

### Installation

```
pip install spymaster
```

### Usage

```
usage: spymaster.py [-h] [-f <format>] [--fn] [-d <entry number>]
                    [--disable-fixup] [-c <cores>] [-t <timezone name>]
                    [--tf <time format>] [--list-tz] [-o <output file>]
                    [-i <input file>] [-v]

Parses a MFT file.

optional arguments:
  -h, --help            show this help message and exit
  -f <format>, --format <format>
                        Format of the output file.
  --fn                  Specifies if the bodyfile format will use the
                        FILE_NAME attribute for the dates. Valid only for
                        bodyfile output.
  -d <entry number>, --dump <entry number>
                        Dumps resident files from the MFT. Pass the entry
                        number to dump the file. The name of the file needs to
                        be specified using the '-o' option.
  --disable-fixup       Disable the application of the fixup array. Should be
                        used only when trying to get MFT entries from memory.
  -c <cores>, --cores <cores>
                        Control how many cores will be used for processing. 0
                        will try to use as many cores as possible, 1 disables
                        multiprocessing.
  -t <timezone name>, --timezone <timezone name>
                        Convert all the times used by the script to the
                        provided timezone. Use '--list-tz' to check available
                        timezones. Default is UTC.
  --tf <time format>    How the time information is printed. Use the same
                        format as in the strftime function.
  --list-tz             Prints a list of all available timezones.
  -o <output file>, --output <output file>
                        The filename and path where the resulting file will be
                        saved.
  -i <input file>, --input <input file>
                        The MFT file to be processed.
  -v, --verbose         Enables verbose/debug mode.
```

#### Observations

- If the deleted file path cannot be found, the root will become `__ORPHAN__`

#### Examples

TODO

## TODO/Roadmap?

- Add option to dump ADS, at the moment can dump only the main datastream

## Features

- Export the MFT to:
  - CSV, JSON and bodyfile
- Skip application of the fixup array
- Dump resident files

## CHANGELOG

### Version 0.3

- Reworked the code to be a little faster
- Updated to new libmft
- Added parallelization
- Made it a little bit more modular


### Version 0.2

- Added csv, json and bodyfile
- Can select if bodyfile will use FILENAME attribute or STANDARD_INFORMATION
- Changed input to option "-i"
- Added option to dump resident files
- Added option to not apply fixup array
- Change the timezone of the dates

### Version 0.1

- Initial commit

## Known problems

TODO

## References:

TODO
