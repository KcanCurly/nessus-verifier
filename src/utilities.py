import os

def savetofile(path, message, mode = "a+"):
    with open(path, mode) as f:
        f.write(message)
        
def get_hosts_from_file(name):
    try:
        with open(name, "r") as file:
            return [line.strip() for line in file if line.strip()] 
    except: return None
    
def confirm_prompt(prompt="Are you sure?", suppress = False):
    extra = " [y/N]: " if not suppress else ""
    while True:
        # Display the prompt and get user input
        response = input(prompt + extra).strip().lower()
        # Default to "n" if input is empty
        if response == "":
            return False
        # Handle valid inputs
        elif response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("Please respond with 'y/yes' or 'n/no'.")