import os

def savetofile(path, message, mode = "a+"):
    with open(path, mode) as f:
        f.write(message)
        
def get_hosts_from_file(name):
    try:
        with open(name, "r") as file:
            return [line.strip() for line in file if line.strip()] 
    except: return None