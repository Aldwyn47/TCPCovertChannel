import socket
import sys
import time

DEST = sys.argv[1]
PORT = int(sys.argv[2])
SCOUT_DELAY = float(sys.argv[3])

try:
    time.sleep(SCOUT_DELAY)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((DEST, PORT))
except:
    ()