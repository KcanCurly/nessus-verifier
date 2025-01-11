def savetofile(path, message, mode = "a+"):
    with open(path, mode) as f:
        f.write(message)
        