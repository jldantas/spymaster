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

TODO

### Usage

```
usage: spymaster.py [-h] [-f <format>] [--fn] [-d <entry number>]
                    [--disable-fixup] [-t <timezone name>] [--list-tz]
                    [-o <output file>] [-i <input file>]

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
  -t <timezone name>, --timezone <timezone name>
                        Convert all the times used by the script to the
                        provided timezone. Use '--list-tz' to check available
                        timezones. Default is UTC.
  --list-tz             Prints a list of all available timezones.
  -o <output file>, --output <output file>
                        The filename and path where the resulting file will be
                        saved.
  -i <input file>, --input <input file>
                        The MFT file to be processed.
```

#### Observations

- If the MFT entry does not have a filename, a standard one will be created,
  with the name `__INVALID__` and the dates as "0" (1601-01-01 00:00:00)
- If the deleted file path cannot be found, the root will become `__ORPHAN__`

#### Examples

TODO

## TODO/Roadmap?

- Add option to dump ADS, at the moment can dump only the main datastream
- Add a more commentaries to the code

## Features

- Export the MFT to:
  - CSV, JSON and bodyfile
- Skip application of the fixup array
- Dump resident files

## CHANGELOG

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
