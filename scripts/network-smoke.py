#!/usr/bin/env python3
"""Run controlled remote echo endpoints or probe them through a local SOCKS5 proxy."""

import argparse
import json
import ipaddress
import signal
import socket
import socketserver
import struct
import threading


# The remote marker distinguishes remote echo replies from unproxied local traffic.
MARKER = b"zion-remote:"


class TcpEcho(socketserver.BaseRequestHandler):
    """Reply to a complete half-closed TCP request with its original bytes and a marker."""

    def handle(self):
        """Read a bounded request through EOF before returning its marked payload."""
        self.request.settimeout(10)
        payload = bytearray()
        while True:
            chunk = self.request.recv(16384)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 1024 * 1024:
                return
        self.request.sendall(MARKER + payload)


class UdpEcho(socketserver.BaseRequestHandler):
    """Return marked UDP payloads only to the requesting endpoint."""

    def handle(self):
        """Send one marked datagram back to its source."""
        payload, listener = self.request
        listener.sendto(MARKER + payload, self.client_address)



class TcpEchoServer(socketserver.ThreadingTCPServer):
    """Choose an explicit listener family for the requested loopback TCP address."""

    def __init__(self, address):
        """Select the listener family before binding the controlled echo handler."""
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, TcpEcho)


class UdpEchoServer(socketserver.UDPServer):
    """Choose an explicit listener family for the requested loopback UDP address."""

    def __init__(self, address):
        """Select the listener family before binding the controlled echo handler."""
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, UdpEcho)


def encode_address(target):
    """Encode a literal IPv4 or IPv6 destination for this bounded SOCKS test probe."""
    address = ipaddress.ip_address(target[0])
    return bytes([1 if address.version == 4 else 4]) + address.packed + struct.pack("!H", target[1])


def serve(host):
    """Expose temporary loopback echo endpoints and print their selected ports as JSON."""
    with TcpEchoServer((host, 0)) as tcp:
        with UdpEchoServer((host, 0)) as udp:
            tcp.daemon_threads = True
            for listener in (tcp, udp):
                threading.Thread(target=listener.serve_forever, daemon=True).start()
            print(json.dumps({"tcp_port": tcp.server_address[1], "udp_port": udp.server_address[1]}), flush=True)
            signal.pause()


def read_exact(stream, size):
    """Receive the requested number of stream bytes or fail on premature EOF."""
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise RuntimeError("unexpected SOCKS5 EOF")
        result.extend(chunk)
    return bytes(result)


def command(proxy, operation, target):
    """Negotiate one SOCKS5 operation and return its control socket and bound address."""
    stream = socket.create_connection(proxy, timeout=15)
    try:
        stream.sendall(b"\x05\x01\x00")
        if read_exact(stream, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 negotiation rejected")
        address = encode_address(target)
        stream.sendall(bytes([5, operation, 0]) + address)
        version, status, reserved, family = read_exact(stream, 4)
        if (version, status, reserved) != (5, 0, 0):
            raise RuntimeError("SOCKS5 command failed: {}".format(status))
        if family not in (1, 4):
            raise RuntimeError("unexpected SOCKS5 bound address family")
        native = socket.AF_INET if family == 1 else socket.AF_INET6
        size = 4 if family == 1 else 16
        bound = (socket.inet_ntop(native, read_exact(stream, size)), struct.unpack("!H", read_exact(stream, 2))[0])
        return stream, bound
    except Exception:
        stream.close()
        raise


def probe_tcp(proxy, port, host="127.0.0.1"):
    """Verify a 128 KiB TCP payload and response after a half-close through SOCKS5."""
    stream, _ = command(proxy, 1, (host, port))
    with stream:
        payload = bytes(range(256)) * 512
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = stream.recv(16384)
            if not chunk:
                break
            response.extend(chunk)
        if response != MARKER + payload:
            raise RuntimeError("remote TCP payload mismatch")
        return len(payload)


def probe_udp(proxy, port, host="127.0.0.1"):
    """Verify five marked UDP replies with bounded retries for unreliable delivery."""
    control, relay = command(proxy, 3, ("0.0.0.0", 0))
    with control, socket.socket(socket.AF_INET6 if ":" in relay[0] else socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("::1" if ":" in relay[0] else "127.0.0.1", 0))
        udp.settimeout(2)
        header = b"\x00\x00\x00" + encode_address((host, port))
        for sequence in range(5):
            payload = b"udp-probe-" + str(sequence).encode()
            for attempt in range(3):
                udp.sendto(header + payload, relay)
                try:
                    response, source = udp.recvfrom(65535)
                except socket.timeout:
                    if attempt == 2:
                        raise
                    continue
                if source[:2] != relay or response != header + MARKER + payload:
                    raise RuntimeError("remote UDP payload or source mismatch")
                break
    return 5


def main():
    """Select remote echo serving or a bounded local SOCKS5 smoke probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--target-host", default="127.0.0.1", choices=["127.0.0.1", "::1"])
    parser.add_argument("--socks", default="127.0.0.1:1080")
    parser.add_argument("--tcp-port", type=int)
    parser.add_argument("--udp-port", type=int)
    args = parser.parse_args()
    if args.serve:
        serve(args.target_host)
        return
    if args.tcp_port is None or args.udp_port is None:
        parser.error("--tcp-port and --udp-port are required for probing")
    host, port = args.socks.rsplit(":", 1)
    proxy = (host.strip("[]"), int(port))
    print(json.dumps({"tcp_bytes": probe_tcp(proxy, args.tcp_port, args.target_host), "udp_replies": probe_udp(proxy, args.udp_port, args.target_host), "status": "passed"}))


# Execute the requested smoke-test role when invoked as a script.
if __name__ == "__main__":
    main()
