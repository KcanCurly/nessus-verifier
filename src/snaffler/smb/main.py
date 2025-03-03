from impacket.smbconnection import SMBConnection
import argparse

def list_files_recursively(conn, share, directory="anon-share"):
    """
    Recursively lists all files and directories in a given SMB share.
    """
    try:
        print(1)
        # List contents of the current directory
        files = conn.listPath(share, directory)
        print(2)
        for file in files:
            filename = file.get_longname()
            if filename in [".", ".."]:  # Skip current and parent directory links
                continue

            full_path = filename
            
            if file.is_directory():
                print(f"[DIR] {full_path}")
                # Recursively list the contents of subdirectories
                # list_files_recursively(conn, share, full_path)
            else:
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
    
    target = "192.168.48.167"  # Change to the target's IP or hostname
    username = "Administrator"
    password = "Password1!"
    domain = "lab.local"  # Change if needed
    share = "C$"  # Admin shares (C$, D$, etc.) require admin access

    try:
        # Establish SMB connection
        conn = SMBConnection(target, target)
        conn.login(username, password, domain)

        print(f"Connected to {target}, listing files in {share}:")
        list_files_recursively(conn, share)

        conn.close()
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    main()
