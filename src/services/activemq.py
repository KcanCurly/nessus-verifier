import stomp
import argparse
import time

class Listener(stomp.ConnectionListener):
# Override the methods on_error and on_message provides by the
# parent class
    def on_error(self, headers, message):
        print('received an error "%s"' % message)# Print out the message received    def on_message(self, headers, message):
        
    def on_message(self, headers, message):
        print('received a message "%s"' % message)

def enumerate_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    for host in l:
        try:
            h = [host]
            conn = stomp.Connection(h)
            conn.set_listener('', Listener())
            conn.connect('admin', 'admin', wait = True)
            conn.subscribe(destination='/queue/queue-1', id=1, ack='auto')
            time.sleep(5)
            conn.disconnect()
        except Exception as e: print(e)

def main():
    parser = argparse.ArgumentParser(description="ActiveMQ module of nessus-verifier.")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_all = subparsers.add_parser("all", help="Runs all modules (Except post module")
    parser_all.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_all.add_argument("-u", "--username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_all.add_argument("-p", "--password", type=str, default="", help="Username (Default = '')")
    parser_all.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_all.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_all.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_all.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_all.set_defaults(func=all)