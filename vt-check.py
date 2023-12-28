#!/usr/bin/env python

__description__ = "check IoCs [IPs/hashs/URLs] in VirusTotal using virustotal APIv3"
__author__ = "Omar Aljammaz"
__date__ = "25/12/2023"


import argparse
import sys
import requests
import time
import ipaddress

API_KEY = "<add_your_api_here>"
headers = {"Content-Type": "application/json", "x-apikey": API_KEY}

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


def identify_ioc(IoC):
    try:
        ipaddress.ip_address(IoC)
        return "is_ip"
    except ValueError:
        pass
    if len(IoC) == 32 or len(IoC) == 64 or len(IoC) == 40:
        if "." in IoC:
            return "is_url"
        return "is_hash"
    elif IoC.startswith("http"):
        return "is_url"
    else:
        print(f"error in identifying IOC: {IoC}")


def VT_ckeck(IoC):
    for i in range(len(IoC)):
        ioc_type = identify_ioc(IoC[i])
        # print(ioc_type)
        if ioc_type == "is_ip":
            url = vt_ip_link
        elif ioc_type == "is_hash":
            url = vt_hash_link
        else:
            url = vt_url_link

        try:
            url = f"{url}{IoC[i]}"
            response = requests.get(url, headers=headers)
        except Exception:
            print(f"Can't send a request to: {url}{IoC[i]}")

        decodedResponse = response.json()
        if not response.ok:
            if "not found" in decodedResponse["error"]["message"]:
                print(f"{IoC[i]} NOT found")
                continue
        else:
            print(
                f"{IoC[i]} flaged as malicious in: {decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]} Vendors"
            )
        time.sleep(15)


def main():
    args = parse_arguments()

    try:
        with open(args.list) as f:
            IoC = f.read().splitlines()
    except Exception:
        print(f"Error: failed to open {args.list}", file=sys.stderr)
        sys.exit(1)

    VT_ckeck(IoC)


if __name__ == "__main__":
    try:
        if API_KEY == "<add_your_api_here>":
            print(
                r'''add you VT API in line 14 in .py file: API_KEY = "<add_yout_api_here>"'''
            )
        else:
            main()

    except KeyboardInterrupt:
        sys.exit(1)
