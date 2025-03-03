from impacket.smbconnection import SMBConnection
import argparse
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file

MAX_FILE_SIZE_MB = 100

def can_read_file(conn, file):
    pass

def list_files_recursively(conn, share, rules, directory="*"):
    """
    Recursively lists all files and directories in a given SMB share.
    """
    try:
        # List contents of the current directory
        files = conn.listPath(share, directory)
        for file in files:
            filename = file.get_longname()
            if filename in [".", ".."]:  # Skip current and parent directory links
                continue

            full_path = directory.replace("*", "")  + filename
            
            if file.is_directory():
                if not rules.enum_directory(full_path)[0]:continue
                print(f"[DIR] {share.replace("$", "")}:/{full_path}")
                # Recursively list the contents of subdirectories
                list_files_recursively(conn, share, rules, full_path + "/*")
            elif file.is_file():
                print(file.get_filesize())
                enum_file = rules.enum_file(full_path)
                if not enum_file[0] or not can_read_file(conn, full_path):continue
                print(f"[FILE] {full_path}")

    except Exception as e:
        print(f"Error accessing {directory}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser.add_argument("-e", "--error", action="store_true", help="Prints errors")
    args = parser.parse_args()
    
    target = "192.168.48.167"  # Change to the target's IP or hostname
    username = "Administrator"
    password = "Password1!"
    domain = "lab.local"  # Change if needed
    share = "C$"  # Admin shares (C$, D$, etc.) require admin access
    rules = SnafflerRuleSet.load_default_ruleset()
    try:
        # Establish SMB connection
        conn = SMBConnection(target, target)
        conn.login(username, password, domain)

        if args.verbose: print(f"Connected to {target}, listing files in {share}:")
        list_files_recursively(conn, share, rules)

        conn.close()
    except Exception as e:
        if args.error: print(f"Failed to connect: {e}")
