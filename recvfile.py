import socket, sys
out, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(1)
c, _ = s.accept()
with open(out, "wb") as f:
    while chunk := c.recv(65536):
        f.write(chunk)
