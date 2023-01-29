#!/usr/bin/env python3
import socket
import sys
import threading

#
# A list comprehension showing all printable chars
ASCII = [chr(i) if len(repr(chr(i))) == 3 else '.' for i in range(0, 256)]
HEX_FILTER = ''.join(ASCII)


# A function that takes a string as an input and outputs the hex dump of it.

def hexdump(text, show=True, length=16):
    # The function will read the text and output lines of 16 bytes each representing the hex code and the ascii
    # So we parsed a string now and first we need to replace chars that are not ascii with .

    if isinstance(text, bytes):
        text = text.decode()

    result = []  # An array holding the lines of the output each as a string
    width = 3
    for i in range(0, len(text), length):
        word = text[i:i + length]
        chunk = ' '.join([f'{ord(c):02x}' for c in word])
        printable = word.translate(HEX_FILTER)
        # print(chunk)
        result.append(f'{i:04x}  {chunk:<{16 * 3}}  {printable}')
    for line in result:
        print(line)


# For receiving both local and remote data. We are passing a socket object to the function that can be
# a Local or remote socket.
def receive_from(connection):
    buffer = b""  # defining an empty binary buffer of object type.
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(1024)
            if not data:
                break
            buffer += data

    except Exception as F:
        pass
    return buffer


def request_handler(buffer):
    return buffer


def response_handler(buffer):
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>] Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote")
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            line = "[<==] Received %d bytes from remote." % len(remote_buffer)
            print(line)
            hexdump(remote_buffer)
            remote_buffer = request_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No More Data. Closing Connections")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print("problem on bind: %r" % e)
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        line = "[==>] Received incoming connection from %s:%d." % (addr[0], addr[1])
        print(line)
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host,
                  remote_port, receive_first)
        )
        proxy_thread.start()


# This is a script that will implement a tcp proxy via python
def main():
    if len(sys.argv[1:]) !=5:
        print("Usage: ./proxy.py [localhost] [localport] ", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
