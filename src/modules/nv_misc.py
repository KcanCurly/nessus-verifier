import argparse, argcomplete
from src.utilities import utilities
from src.utilities.utilities import get_cves

def main():
    parser = argparse.ArgumentParser(description="Misc functions for nv.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cve_parser = subparsers.add_parser("cve", help="Search for cves for given cpe")
    cve_parser.add_argument("cpe", type=str, help="cpe to search")
    cve_parser.add_argument("-c", "--count", type=int, default=10, help="cve limit (Default: 10)")

    latest_parser = subparsers.add_parser("latest", help="Search for latest application version")
    latest_parser.add_argument("app", type=str, help="application name to search")
    
    args = parser.parse_args()
    argcomplete.autocomplete(parser)

    if args.command == "cve":
        cves = get_cves(args.cpe, limit=args.count)
        print(", ".join(cves))
    elif args.command == "latest":
        latest_versions = utilities.get_latest_version(args.app.lower())
        print(", ".join(latest_versions)) # type: ignore
