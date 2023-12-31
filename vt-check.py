#!/usr/bin/env python

__description__ = "check IoCs [IPs/hashs/URLs] in VirusTotal using virustotal APIv3"
__author__ = "Omar Aljammaz"
__date__ = "25/12/2023"


import argparse
import sys
import requests
import time
import ipaddress

api_kay = "<add_your_api_here>"
headers = {"Content-Type": "application/json", "x-apikey": api_kay}

url = ""
vt_hash_link = "https://www.virustotal.com/api/v3/files/"
vt_ip_link = "https://www.virustotal.com/api/v3/ip_addresses/"
vt_url_link = "https://www.virustotal.com/api/v3/domains/"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=__description__,
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=48),
    )
    required = parser.add_argument_group("required")
    optional = parser.add_argument_group("optional")
    required.add_argument(
        "-l",
        "--list",
        type=str,
        metavar="<PATH>",
        help="path to .txt file hashs list",
        required=True,
    )

    optional.add_argument(
        "-h", "--help", action="help", help="show this help message and exit"
    )
    return parser.parse_args()


def identify_ioc(ioc):
    try:
        ipaddress.ip_address(ioc)
        return "is_ip"
    except ValueError:
        pass
    if len(ioc) == 32 or len(ioc) == 64 or len(ioc) == 40:
        if "." in ioc:
            return "is_url"
        return "is_hash"
    elif ioc.startswith("http"):
        return "is_url"
    else:
        print(f"error in identifying IOC: {ioc}")


def VT_ckeck(ioc):
    for i in range(len(ioc)):
        ioc_type = identify_ioc(ioc[i])
        if ioc_type == "is_ip":
            url = vt_ip_link
        elif ioc_type == "is_hash":
            url = vt_hash_link
        else:
            url = vt_url_link

        try:
            url = f"{url}{ioc[i]}"
            response = requests.get(url, headers=headers)
        except Exception:
            print(f"Can't send a request to: {url}")

        decodedResponse = response.json()
        if not response.ok:
            if "not found" in decodedResponse["error"]["message"]:
                print(f"{ioc[i]} NOT found")
                continue
        else:
            print(
                f"{ioc[i]} flaged as malicious in: {decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]} Vendors"
            )
        time.sleep(15)


def main():
    args = parse_arguments()

    try:
        with open(args.list) as f:
            ioc = f.read().splitlines()
    except Exception:
        print(f"Error: failed to open {args.list}", file=sys.stderr)
        sys.exit(1)

    VT_ckeck(ioc)


if __name__ == "__main__":
    try:
        if api_kay == "<add_your_api_here>":
            print(
                r'''add you VT API in line 14 in .py file: api_kay = "<add_yout_api_here>"'''
            )
        else:
            main()

    except KeyboardInterrupt:
        sys.exit(1)
