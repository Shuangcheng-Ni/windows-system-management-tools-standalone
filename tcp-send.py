import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    for i in range(3):
        try:
            client_socket.connect((HOST, PORT))
            break
        except Exception as e:
            ex = e
            time.sleep(1)
    else:
        raise ex
    while byte := sys.stdin.buffer.read(1):
        client_socket.sendall(byte)
