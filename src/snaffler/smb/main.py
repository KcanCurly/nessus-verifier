from impacket.smbconnection import SMBConnection

def list_files_recursively(conn, share, directory=""):
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

            full_path = f"{directory}\\{filename}" if directory else filename

            if file.is_directory():
                print(f"[DIR] {full_path}")
                # Recursively list the contents of subdirectories
                list_files_recursively(conn, share, full_path)
            else:
                print(f"[FILE] {full_path}")

    except Exception as e:
        print(f"Error accessing {directory}: {e}")

def main():
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
