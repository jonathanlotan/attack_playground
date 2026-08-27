#!/usr/bin/env python3
"""
babychal - a tiny demo "attack endpoint" for the playground.

listens on tcp/1337 (one of the ports allowlisted in attack_network_endpoints.conf,
so a restricted guest is allowed to reach it on the bridge gateway). on each
connection it hands out a fresh two-number puzzle; send back the product and it
reveals the flag. the point is only to exercise a real bidirectional exchange over
an allowed endpoint - read a dynamic prompt, compute, reply, get the reward.

run on the host:  python3 challenges/babychal_1337.py
solve from a guest: nc <gateway-ip> 1337   (then answer the prompt)
"""

import random
import socket
import threading

HOST = "0.0.0.0"          # reachable at the bridge gateway ip from a guest
PORT = 1337
FLAG = "flag{playground_1337_pwned}"


def handle(conn, addr):
    conn.settimeout(30)
    try:
        a = random.randint(100, 999)
        b = random.randint(100, 999)
        conn.sendall(
            (
                "=== attack_playground :: babychal @ 1337 ===\n"
                "solve the puzzle to earn the flag.\n"
                f"compute a*b where a={a} and b={b}.\n"
                "send the number followed by a newline.\n"
                "> "
            ).encode()
        )

        data = b""
        while b"\n" not in data:
            chunk = conn.recv(1024)
            if not chunk:
                return
            data += chunk
            if len(data) > 4096:
                break

        try:
            answer = int(data.strip())
        except ValueError:
            conn.sendall(b"that's not a number. bye.\n")
            return

        if answer == a * b:
            conn.sendall(f"correct! here is your flag:\n{FLAG}\n".encode())
        else:
            conn.sendall(f"wrong. {a}*{b} != {answer}. bye.\n".encode())
    except socket.timeout:
        try:
            conn.sendall(b"timeout. bye.\n")
        except OSError:
            pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    print(f"babychal listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
