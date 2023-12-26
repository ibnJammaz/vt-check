# access2csv

check IoCs [IPs/hashs/urls] in VirusTotal using virustotal APIv3

## Usage
add you VT API in line 4 in .py file: API_KEY = "<add_your_api_here>"

```console
usage: vt-check.py -l <PATH_to_txt_file_containing_IoCs> [-h]

check hashes in VT using VT API

required:
  -l <PATH>, --list <PATH>  path to .txt file hashs list

optional:
  -h, --help                show this help message and exit
```

## Requirements

Python 3.6 or later