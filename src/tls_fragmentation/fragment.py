import logging
import select
import socket
import struct
import threading

HOST = "127.0.0.1"
PORT = 1080
SPLIT_INDEX = 5

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


def manage_session(client_sock: socket.socket) -> None:
    """Manages the SOCKS5 session and SNI fragmentation.
    RFC 1928: SOCKS Protocol Version 5
    """
    remote_sock = None
    try:
        data = client_sock.recv(2)
        if not data or len(data) != 2:
            return

        ver, nmethods = struct.unpack("!2B", data)
        if ver != 0x05:
            logger.warning(f"Unsupported SOCKS version: {ver}")
            return

        methods_raw = client_sock.recv(nmethods)
        if not methods_raw or len(methods_raw) != nmethods:
            return

        methods = struct.unpack(f"!{nmethods}B", methods_raw)
        if 0x00 not in methods:
            logger.warning("Client does not support 'No Authentication' method")
            return

        client_sock.sendall(b"\x05\x00")  # NO AUTHENTICATION REQUIRED

        # SOCKS5 Connection Request
        req = client_sock.recv(4)
        if not req or len(req) != 4:
            return

        ver, cmd, _, atyp = struct.unpack("!4B", req)
        if ver != 0x05:
            logger.warning(f"Unsupported SOCKS version: {ver}")
            return
        if cmd != 0x01:
            logger.warning(f"CMD is {hex(cmd)} and not 0x01 (CONNECT)")
            return

        match atyp:
            case 1:  # IPv4
                dst_addr = socket.inet_ntoa(client_sock.recv(4))
            case 3:  # Domain Name
                addr_len = client_sock.recv(1)[0]
                dst_addr = client_sock.recv(addr_len).decode("utf-8")
            case 4:  # IPv6
                dst_addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            case _:
                logger.warning(f"Address Type unknown: {hex(atyp)}")
                return

        (dst_port,) = struct.unpack("!H", client_sock.recv(2))

        remote_sock = socket.create_connection((dst_addr, dst_port), timeout=10)

        # Disable Nagle's Algorithm to force distinct TCP packets
        remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        client_hello_fragmented = False
        while True:
            r_list, _, _ = select.select([client_sock, remote_sock], [], [], 60)
            if not r_list:
                break

            if client_sock in r_list:
                data = client_sock.recv(4096)
                if not data:
                    break

                if (
                    not client_hello_fragmented
                    and len(data) > SPLIT_INDEX + 1
                    and data[0] == 0x16  # TLS Record Header
                    and data[5] == 0x01  # TLS ClientHello Handshake Type
                ):
                    remote_sock.sendall(data[:SPLIT_INDEX])
                    remote_sock.sendall(data[SPLIT_INDEX:])
                    client_hello_fragmented = True
                else:
                    remote_sock.sendall(data)

            if remote_sock in r_list:
                data = remote_sock.recv(4096)
                if not data:
                    break
                client_sock.sendall(data)

    except Exception:
        logger.exception("Session failed")
    finally:
        client_sock.close()
        if remote_sock:
            remote_sock.close()


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    logger.info(f"SOCKS5 Proxy Server running on {HOST}:{PORT}")

    while True:
        client_sock, _ = server.accept()
        t = threading.Thread(target=manage_session, args=(client_sock,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
