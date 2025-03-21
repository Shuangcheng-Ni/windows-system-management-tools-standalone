import ctypes
import socket
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1])

dll = ctypes.CDLL("ucrtbase.dll")
putchar = lambda byte: dll.putchar(int.from_bytes(byte, "little"))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    server_socket.settimeout(10)
    client_socket, client_address = server_socket.accept()
    server_socket.settimeout(None)
    with client_socket:
        while byte := client_socket.recv(1):
            putchar(byte)
