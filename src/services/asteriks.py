import subprocess

def version_nv(file, port):
    command = ["sippts", "scan", "-f", file, "-r", port, "-p", "all", "-o", "nv-asteriks-data"]
    try:
        subprocess.run(command, text=True)
        with open("nv-asteriks-data") as f:
            print(f.read())

    except Exception as e: print(e)

def version_console(args):
    version_nv(args.file)

def main(commandparser):
    parser_task1 = commandparser.add_parser("asteriks")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks Asteriks version")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("-p", "--port", type=str, default="", help="sippts port argument (Default = 5030-5080)")
    parser_version.set_defaults(func=version_console)