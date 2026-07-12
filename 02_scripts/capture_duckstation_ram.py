from __future__ import annotations

import argparse
import ctypes
import json
from ctypes import wintypes
from pathlib import Path


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
RAM_SIZE = 0x200000


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("base_address", ctypes.c_void_p),
        ("allocation_base", ctypes.c_void_p),
        ("allocation_protect", wintypes.DWORD),
        ("region_size", ctypes.c_size_t),
        ("state", wintypes.DWORD),
        ("protect", wintypes.DWORD),
        ("type", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MemoryBasicInformation),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t


def read_memory(process: int, address: int, size: int) -> bytes | None:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        process, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)
    )
    if not ok or read.value != size:
        return None
    return buffer.raw


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read DuckStation PS1 RAM without attaching a debugger."
    )
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--signature-json", type=Path)
    parser.add_argument("--reference-offset", default=0x11B000, type=lambda v: int(v, 0))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--base", type=lambda v: int(v, 0))
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args()

    reference = args.reference.read_bytes()
    signature = reference[args.reference_offset : args.reference_offset + 0x1000]
    if args.signature_json is not None:
        saved = json.loads(args.signature_json.read_text(encoding="utf-8"))
        signature = bytes.fromhex(saved["snapshot_hex"])
        args.reference_offset = int(saved["snapshot_address"], 0) & 0x1FFFFFFF
    if not signature:
        raise ValueError("signature is empty")

    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, args.pid
    )
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    candidates: list[int] = []
    try:
        address = 0
        info = MemoryBasicInformation()
        while kernel32.VirtualQueryEx(
            process, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        ):
            region_start = int(info.base_address or 0)
            region_end = region_start + info.region_size
            readable = (
                info.state == MEM_COMMIT
                and not (info.protect & (PAGE_NOACCESS | PAGE_GUARD))
                and info.region_size >= 0x1000
            )
            if readable:
                chunk_size = 0x100000
                overlap = len(signature) - 1
                probe = region_start
                tail = b""
                while probe < region_end:
                    size = min(chunk_size, region_end - probe)
                    data = read_memory(process, probe, size)
                    if data is not None:
                        searchable = tail + data
                        found = searchable.find(signature)
                        while found >= 0:
                            match_address = probe - len(tail) + found
                            base = match_address - args.reference_offset
                            ram = read_memory(process, base, RAM_SIZE)
                            if ram is not None:
                                candidates.append(base)
                            found = searchable.find(signature, found + 1)
                        tail = searchable[-overlap:] if overlap else b""
                    else:
                        tail = b""
                    probe += size
            address = max(region_end, address + 0x1000)

        candidates = sorted(set(candidates))
        for candidate in candidates:
            pointer = read_memory(process, candidate + 0x1FA558, 4)
            pointer_value = int.from_bytes(pointer, "little") if pointer else 0
            print(f"candidate=0x{candidate:X} script_pointer=0x{pointer_value:08X}")

        if args.base is not None:
            candidates = [args.base]
        if len(candidates) != 1 or args.list_only:
            return
        if args.output is None:
            raise ValueError("--output is required when exactly one candidate is found")
        ram = read_memory(process, candidates[0], RAM_SIZE)
        if ram is None:
            raise RuntimeError("RAM candidate became unreadable")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(ram)
        print(f"wrote {args.output}")
    finally:
        kernel32.CloseHandle(process)


if __name__ == "__main__":
    main()
