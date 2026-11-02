import socket, sys
f, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with socket.create_connection((host, port)) as s, open(f, "rb") as fh:
    while chunk := fh.read(65536):
        s.sendall(chunk)
