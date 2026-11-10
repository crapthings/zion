#!/usr/bin/env python3
"""Probe small and QUIC-sized UDP packets without changing routes or proxy configuration."""

import argparse
import json
import socket
import sys
import time


# These payload sizes distinguish general UDP reachability from large-packet failures.
SIZES = (64, 1200)


def serve(port, nonce, lifetime):
    """Echo only matching test packets until a fixed lifetime expires."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", port))
        deadline = time.monotonic() + lifetime
        print(json.dumps({"event": "ready", "port": listener.getsockname()[1]}), flush=True)
        while time.monotonic() < deadline:
            listener.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                packet, source = listener.recvfrom(65535)
            except socket.timeout:
                break
            if len(packet) in SIZES and packet.startswith(nonce):
                listener.sendto(packet, source)
                print(json.dumps({"event": "echo", "source": source[0], "bytes": len(packet)}), flush=True)


def probe(remote, nonce, interface):
    """Measure bounded UDP echo success using the current route or one macOS interface."""
    host, port = remote.rsplit(":", 1)
    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        if interface:
            if sys.platform != "darwin":
                raise RuntimeError("--interface currently supports macOS only")
            # The macOS SDK defines IP_BOUND_IF as 25 for per-socket interface selection.
            sender.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
        sender.connect((host, int(port)))
        sender.settimeout(2)
        for size in SIZES:
            packet = nonce + bytes(size - len(nonce))
            received = False
            failure = None
            for _ in range(2):
                try:
                    sender.send(packet)
                    response = sender.recv(65535)
                    if response == packet:
                        received = True
                        break
                    failure = "unexpected_response"
                except OSError as error:
                    failure = type(error).__name__ + ": " + str(error)
            results.append({"bytes": size, "received": received, "failure": None if received else failure})
    print(json.dumps({"interface": interface or "system_route", "results": results}), flush=True)
    return all(result["received"] for result in results)


def main():
    """Select temporary echo serving or a bounded UDP path probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=38443)
    parser.add_argument("--lifetime", type=float, default=45)
    parser.add_argument("--remote")
    parser.add_argument("--interface")
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    nonce = args.nonce.encode("ascii")
    if not 16 <= len(nonce) <= 64:
        parser.error("--nonce must contain 16 to 64 ASCII characters")
    if args.serve:
        if not 0 < args.lifetime <= 120:
            parser.error("--lifetime must be between 0 and 120 seconds")
        serve(args.port, nonce, args.lifetime)
    else:
        if not args.remote:
            parser.error("--remote is required for probing")
        if not probe(args.remote, nonce, args.interface):
            sys.exit(1)


# Run only the explicitly requested probe role when invoked as a script.
if __name__ == "__main__":
    main()
