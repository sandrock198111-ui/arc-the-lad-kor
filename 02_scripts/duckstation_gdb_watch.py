from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path


def packet(command: str) -> bytes:
    payload = command.encode("ascii")
    return b"$" + payload + b"#" + f"{sum(payload) & 0xFF:02x}".encode("ascii")


class RspClient:
    def __init__(self, host: str, port: int) -> None:
        self.socket = socket.create_connection((host, port), timeout=10)
        self.socket.settimeout(None)

    def close(self) -> None:
        self.socket.close()

    def _read_packet(self) -> str:
        while True:
            byte = self.socket.recv(1)
            if byte == b"+":
                continue
            if byte == b"-":
                raise RuntimeError("GDB server rejected the previous packet")
            if byte != b"$":
                continue

            body = bytearray()
            while True:
                next_byte = self.socket.recv(1)
                if next_byte == b"#":
                    break
                body.extend(next_byte)
            checksum = self.socket.recv(2)
            expected = f"{sum(body) & 0xFF:02x}".encode("ascii")
            if checksum.lower() != expected:
                self.socket.sendall(b"-")
                continue
            self.socket.sendall(b"+")
            return body.decode("ascii", errors="replace")

    def request(self, command: str) -> str:
        self.socket.sendall(packet(command))
        return self._read_packet()

    def continue_until_stop(self) -> str:
        self.socket.sendall(packet("c"))
        return self._read_packet()

    def resume(self) -> None:
        self.socket.sendall(packet("c"))


def read_memory(client: RspClient, address: int, size: int) -> bytes:
    chunks: list[bytes] = []
    for offset in range(0, size, 0x400):
        length = min(0x400, size - offset)
        response = client.request(f"m{address + offset:x},{length:x}")
        if response.startswith("E"):
            raise RuntimeError(f"memory read failed at 0x{address + offset:08X}: {response}")
        chunks.append(bytes.fromhex(response))
    return b"".join(chunks)


def write_trace(
    output: Path,
    *,
    watch_address: int,
    watch_size: int,
    snapshot_address: int | None,
    status: str,
    hits: list[dict[str, object]],
) -> None:
    result = {
        "status": status,
        "watch_address": f"0x{watch_address:08X}",
        "watch_size": watch_size,
        "hits": hits,
        "snapshot_address": (
            f"0x{snapshot_address:08X}" if snapshot_address is not None else None
        ),
    }
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One persistent DuckStation GDB watchpoint session."
    )
    parser.add_argument("--watch-address", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--watch-size", default=1, type=lambda value: int(value, 0))
    parser.add_argument("--snapshot-address", type=lambda value: int(value, 0))
    parser.add_argument("--snapshot-size", default=0x80, type=lambda value: int(value, 0))
    parser.add_argument("--accept-value-min", type=lambda value: int(value, 0))
    parser.add_argument("--accept-value-max", type=lambda value: int(value, 0))
    parser.add_argument("--max-hits", default=32, type=int)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=2345, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    client = RspClient(args.host, args.port)
    emulation_stopped = True
    try:
        # DuckStation stops when this single client connects. Configure first, then resume.
        watch_response = client.request(
            f"Z2,{args.watch_address:x},{args.watch_size:x}"
        )
        if watch_response != "OK":
            raise RuntimeError(f"watchpoint setup failed: {watch_response!r}")

        hits: list[dict[str, object]] = []
        accepted = False
        watch_value = 0
        for hit_number in range(1, args.max_hits + 1):
            emulation_stopped = False
            stop_reason = client.continue_until_stop()
            emulation_stopped = True
            registers = client.request("g")
            watch_bytes = read_memory(client, args.watch_address, args.watch_size)
            watch_value = int.from_bytes(watch_bytes[:4], "little")
            snapshot = b""
            if args.snapshot_address is not None:
                snapshot = read_memory(
                    client, args.snapshot_address, args.snapshot_size
                )
            hits.append(
                {
                    "hit": hit_number,
                    "stop_reason": stop_reason,
                    "watch_value": f"0x{watch_value:08X}",
                    "registers_hex": registers,
                    "snapshot_hex": snapshot.hex(" "),
                }
            )
            write_trace(
                args.output,
                watch_address=args.watch_address,
                watch_size=args.watch_size,
                snapshot_address=args.snapshot_address,
                status="tracing",
                hits=hits,
            )
            print(
                f"watchpoint hit {hit_number}: {stop_reason} "
                f"value=0x{watch_value:08X}",
                flush=True,
            )

            if args.accept_value_min is None:
                accepted = True
            elif (
                args.accept_value_max is not None
                and args.accept_value_min <= watch_value < args.accept_value_max
            ):
                accepted = True
            if accepted:
                break

        if not accepted:
            raise RuntimeError(
                f"no accepted watch value after {args.max_hits} hits; "
                f"last=0x{watch_value:08X}"
            )

        write_trace(
            args.output,
            watch_address=args.watch_address,
            watch_size=args.watch_size,
            snapshot_address=args.snapshot_address,
            status="accepted",
            hits=hits,
        )
        print(f"watchpoint hit: {stop_reason}")
        print(f"wrote {args.output}")
    finally:
        # Never leave the user's emulator halted after a trace attempt.
        if emulation_stopped:
            try:
                client.resume()
            except (OSError, RuntimeError, socket.timeout):
                pass
        client.close()


if __name__ == "__main__":
    main()
