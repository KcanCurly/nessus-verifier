import argparse
from src.utilities.utilities import get_cves

def main():
    parser = argparse.ArgumentParser(description="Misc functions for nv.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cve_parser = subparsers.add_parser("cve", help="Search for cves for given cpe")
    cve_parser.add_argument("cpe", required=True, type=str, help="cpe to search")
    cve_parser.add_argument("-c", "--count", type=int, default=10, help="cve limit (Default: 10)")
    

    args = parser.parse_args()

    cves = get_cves(args.cpe, limit=args.count)

    print(", ".join(cves))
