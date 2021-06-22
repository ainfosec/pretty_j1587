# `pretty_1587`

This is a tool for getting detailed decodings of J1587/J1708 (and J2497) messages using the J1587 and J1708 specification PDFs as a reference.

Input is some sort of delimited list of bytes that may be reformatted to fit the form ` XX[,..] `. See the `-j CANON` options for the various file formats supported. By default, `pretty_j1587` will read input with a sequence of hex bytes, ignoring delimiters, timestamps, interface names and comments. For example, all of the following are valid by default:

* `0a,00` (the output of the `j1708_logger.py` script for https://github.com/TruckHacking/py-hv-networks)
* `(123123123.123123) j1708 0a00 ; ABS lamp` (the output of the `j1708dump.py` command of https://github.com/TruckHacking/plc4trucksduck)

Output is a printout of details about the message.

Input can be from stdin, sockets or files. 


## Usage
```
usage: pretty_j1587.py [-h] [-c CUSTOMDB] [-d] [-f [FILENAMES]] [-j CANON]
                       [-l [{critical,error,info,debug,notset}]] [-n] [-p]
                       [-t T] [-u U] [--interface [{j1708,j1708_2,plc}]]
                       [-v [{0,1,2}]] [-w [PID [PID ...]]] [-x] [--json]
                       [--format]

Program to make sense of logged J1708/J1587 data

optional arguments:
  -h, --help            show this help message and exit
  -c CUSTOMDB, --customdb CUSTOMDB
                        The filename of the file that contains the custom
                        database in JSON format
  -d                    Disable default (grepable) output
  -f [FILENAMES], --filenames [FILENAMES]
                        The filename(s) of the file(s) that contain(s) the
                        messages. Use - for stdin
  -j CANON, --canon CANON
                        Use this function to reformat each line of input for
                        parsing
  -l [{critical,error,info,debug,notset}]
                        Set the minimum level log level
  -n, --nocache         Parse the J-specs every time command is run and
                        generate a new cache file
  -p                    Print packet delimeters
  -t T                  Define a TCP port to use as input
  -u U                  Define a UDP port to use as input
  --interface [{j1708,j1708_2,plc}]
                        choose the (TruckDuck) interface to dump from. NB:
                        also enables --checksums
  -v [{0,1,2}]          Set the verbosity for regular output
  -w [PID [PID ...]], --whitelist [PID [PID ...]]
                        List of PIDs to be parsed, ignoring other messages
  -x, --checksums       Tells the parser that the messages contain checksums
  --json                Print JSON output as opposed to the default
  --format              Pretty print the JSON output
```
The more verbosity, the more detail is printed about a given message.
For example


### No verbosity
```
MSG: [0x89,0xf5,0x4,0xe1,0x0,0x0,0x0]
MID 0x89 (137):  Brakes, Trailer #1
PID 0xf5 (245): Total Vehicle Distance
  DATA: 0x4, 0xe1, 0x0, 0x0, 0x0
```


### Verbosity == 1
```
MSG: [0x89,0xf5,0x4,0xe1,0x0,0x0,0x0]
MID 0x89 (137):  Brakes, Trailer #1
PID 0xf5 (245): Total Vehicle Distance
  _Resolution  : 0.161 km (0.1 mi)
  _MaxRange    : 0.0 to 691207984.6 km (0.0 to 429496729.5 mi)
  _UpdatePeriod: 10.0 s
  _DataType    : Unsigned Long Integer
  _DataLength  : 4 Characters
  _Priority    : 7
  DATA: 0x4, 0xe1, 0x0, 0x0, 0x0
    0x04 - Number of parameter data characters = 4
    0xe1 - Total vehicle distance
    0x00 - Total vehicle distance
    0x00 - Total vehicle distance
    0x00 - Total vehicle distance
```


### Verbosity == 2
```
MSG: [0x89,0xf5,0x4,0xe1,0x0,0x0,0x0]
     ([137, 245, 4, 225, 0, 0, 0])
CLC CHECKSUM: 0x9d (157)
MID 0x89 (137):  Brakes, Trailer #1
PID 0xf5 (245): Total Vehicle Distance
  _Resolution  : 0.161 km (0.1 mi)
  _MaxRange    : 0.0 to 691207984.6 km (0.0 to 429496729.5 mi)
  _UpdatePeriod: 10.0 s
  _DataType    : Unsigned Long Integer
  _DataLength  : 4 Characters
  _Priority    : 7
  DATA: 0x4, 0xe1, 0x0, 0x0, 0x0
    0x04 - Number of parameter data characters = 4
    0xe1 - Total vehicle distance
    0x00 - Total vehicle distance
    0x00 - Total vehicle distance
    0x00 - Total vehicle distance
```


## Requirements 

Requires the latest J1587 and J1708 specifications, which are converted to text 
with pdftotext (using -layout option). Filenames are set in the struct_from_J1587.py file which is used by pretty_j1587.py.


## Examples

### Parse from stdin

```bash
echo "<packet>" | ./pretty_j1587.py  -f -
```


### Print output as formatted JSON from file path, disabling default output format

```bash
./pretty_j1587.py -f <filepath> --json --format -d
```


### Enable logging info and above messages, and use a user defined function to reformat input

```bash
echo "<nexiq_log_packet>" | ./pretty_j1587.py -l info -j canon_nexiq -f -
```
The functions for reformatting specific logs are located in canon_functions.py
These functions take in a line as a message, and output the message in the format:
 ` [int,int,...] `
The current line is passed to the function as an argument. There are a couple of
functions defined as an example and for ease of use.
```bash
echo -e "139,99,22" | ./pretty_j1587.py -f - -v2 -j canon_decimal
```
This will work as previous examples, but takes decimal numbers as input.


### A custom database file is used to give/change values for certain PIDs

```bash
./pretty_j1587.py -f nexiq_j1587.log -c samplejson.def -j canon_nexiq
```
The custom database files are setup as JSON definitions
```bash
{ 
  "mids":
  {
    "131": "Custom mid definition for one three one"
  },
  "pids":
  {
    "84": "A redefined eighty-four (to the moon)"
  },
  "pid_fields":
  { 
    "84": 
        {
            "ByteDef": {
                "a": "velocity toward the moon"
            },
            "DataType": "Unsigned Short Integer",
            "MaximumRange": "0.0 to 205.2 km/h (0.0 to 127.5 mph)",
            "MessagePriority": "4",
            "ParameterDataLength": "1 Character",
            "Resolution": "0.305 km/h (0.5 mph)",
            "Sequence": "a",
            "Summary": "The velocity of the vehicle approaching the moon, from the perspective of one standing on the moon",
            "TransmissionUpdatePeriod": "0.3 s"
        }
   }
}
```
This will override the definitions for PID 84. Some of the output from a Nexiq capture log
reveals the over-ridden definition for 192 using the provided sample custom database file. This 
has full verbosity.
```
MSG: [0x89,0xc0,0x11,0xfe,0x40,0x45,0xac,0x43,0xd4,0xc2,0x40,0x45,0xbf,0x0,0x0,0x9,0x0,0x0,0x1,0x8f]
     ([137, 192, 17, 254, 64, 69, 172, 67, 212, 194, 64, 69, 191, 0, 0, 9, 0, 0, 1, 143])
CLC CHECKSUM: 0xc1 (193)
MID 0x89 (137):  Brakes, Trailer #1
PID 0xc0 (192): A redefined one ninety-two (to somewhere)
  _Resolution  : 0.305 km/h (0.5 mph)
  _MaxRange    : 0.0 to 205.2 km/h (0.0 to 127.5 mph)
  _UpdatePeriod: 0.3 s
  _DataType    : Unsigned Short Integer
  _DataLength  : Variable
  _Priority    : 4
  DATA: 0x11, 0xfe, 0x40, 0x45, 0xac, 0x43, 0xd4, 0xc2, 0x40, 0x45, 0xbf, 0x0, 0x0, 0x9, 0x0, 0x0, 0x1, 0x8f

    0x11 - velocity toward the moon
    0xfe - velocity toward the sun
    0x40 - velocity toward Jupiter
    0x45 - velocity toward the Earth
           OR
         - velocity toward the outerverse
    0xac - velocity toward Jupiter
           OR
         - velocity toward the Earth
    0x43 - velocity toward the moon
           OR
         - velocity toward the Earth
    0xd4 - velocity toward the sun
           OR
         - velocity toward the Earth
    0xc2 - velocity toward the Earth
...
```
Same message in JSON format
```json
{"CLC_CHECKSUM": 89, "DATA": {"192": {"PID_DEF": "A redefined one ninety-two (to somewhere)", "bytes": [12, 254, 68, 0, 1, 70, 191, 0, 0, 9, 0, 0, 1], "bytes_def": {"0": "velocity toward the Earth", "1": "velocity toward the Earth", "9": "velocity toward the Earth", "12": "velocity toward the moon", "68": "velocity toward Jupiter", "70": "velocity toward the moon", "191": "velocity toward the sun", "254": "velocity toward the sun"}, "data_length": "Variable", "data_type": "Unsigned Short Integer", "maximum_range": "0.0 to 205.2 km/h (0.0 to 127.5 mph)", "priority": "4", "resolution": "0.305 km/h (0.5 mph)", "update_period": "0.3 s"}}, "MID": 137, "MID_DEF": "Brakes, Trailer #1", "MSG": [137, 192, 12, 254, 68, 0, 1, 70, 191, 0, 0, 9, 0, 0, 1], "PIDs": [192]}
```
The sequence pointed to in the custom database file *should* be able to handle a couple different methods in the definition. For example in "a,b,c,d/e,c/d,a/d,b/d", the slash means it could be either or. This is reflected in the standard output but not yet in the json. The idea was to try and mimic the different moethods as stated in the J1587 specification.

There may be issues when overriding certain *special* PIDs. For instance, setting up the structure for PID 211 will result in an override of everything as desired, except for the explanation of the data bytes. This may also affect other PIDs within the same message. For most scenarios, these PIDs do not need to be overridden, but there is a TODO item for a remedy at some point.


## Installation

`pretty_j1587.py` requires python3 as well as configparser and hv-networks as captured in `requirements.txt.`

You will also need copies of the J1587 and J1708 specification PDFs and they need to be converted to .txt files using `pdftotext -layout`

```bash
pdftotext -layout J1587_201301.pdf <1587outputfilename>
pdftotext -layout J1708_201609.pdf <1708outputfilename>
```

Now inside the configuration file "config.cfg", modify the file paths to point to 
the output files from above.


## Testing

To be sure at least minimal functionality is provided, run the test file
```bash
python test_pretty_j1587.py
```
Also, included is a script to write random packets to stdout, UDP port 4545, or TCP port 4545.
This can be used to test the functionality of pretty_j1587.py.
```bash
# Terminal 1 - sets up listener
./pretty_j1587.py -t 4545 -p -d --json
# Terminal 2 - spews packets
./fuzzymessages.py T
```
This will write packets to TCP port 4545. For UDP, the argument should be "U". For stdout, run without arguments.


## General TODO:

 - Test different versions of pdftotext (Only 3.03 so far!)
 - Add more test cases 
 - Make sure the SIDs are getting parsed correctly
 - Make JSON output handle the different sorts of byte sequences
 - Check on the customdb when working with special PIDs
 - Maybe try to optimize by not certain work when commandline options are not given
 - Add blacklist option


## Structure related TODO:

Look in "struct_from_J1587.py"
