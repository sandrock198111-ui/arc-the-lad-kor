#!/usr/bin/env python3
"""Locate Psy-Q library functions in a linked PS-X executable.

The Psy-Q LNK object format stores function boundaries, section bytes, and
relocation records.  Relocated instruction words are ignored while matching,
so the remaining bytes can identify the linked SDK routines without guessing
addresses from disassembly alone.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise ValueError(f"unexpected EOF at 0x{self.pos:X}")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def text(self) -> str:
        return self.take(self.u8()).decode("ascii", errors="replace")


@dataclass
class Section:
    name: str
    alignment: int
    data: bytearray = field(default_factory=bytearray)
    patch_base: int = 0

    def append(self, value: bytes) -> None:
        self.patch_base = len(self.data)
        self.data.extend(value)


@dataclass(frozen=True)
class Function:
    section: int
    start: int
    name: str


@dataclass
class ObjectInfo:
    sections: dict[int, Section] = field(default_factory=dict)
    xdefs: dict[str, tuple[int, int]] = field(default_factory=dict)
    functions: list[Function] = field(default_factory=list)
    function_ends: list[tuple[int, int]] = field(default_factory=list)
    patches: list[tuple[int, int, int]] = field(default_factory=list)


def skip_patch_expression(reader: Reader) -> None:
    tag = reader.u8()
    if tag == 0:
        reader.u32()
    elif tag in (2, 4, 12, 22):
        reader.u16()
    else:
        skip_patch_expression(reader)
        skip_patch_expression(reader)


def parse_object(path: Path) -> ObjectInfo:
    reader = Reader(path.read_bytes())
    if reader.take(4) != b"LNK\x02":
        raise ValueError(f"{path} is not a Psy-Q LNK v2 object")

    info = ObjectInfo()
    current_section = 0
    file_line_defined = False

    while reader.pos < len(reader.data):
        record = reader.u8()
        if record == 0:
            break
        if record == 2:
            info.sections[current_section].append(reader.take(reader.u16()))
        elif record == 4:
            reader.u16(); reader.u32()
        elif record == 6:
            current_section = reader.u16()
        elif record == 8:
            info.sections[current_section].append(bytes(reader.u32()))
        elif record == 10:
            patch_type = reader.u8()
            offset = reader.u16()
            absolute = info.sections[current_section].patch_base + offset
            info.patches.append((current_section, absolute, patch_type))
            skip_patch_expression(reader)
        elif record == 12:
            reader.u16()
            section = reader.u16()
            offset = reader.u32()
            name = reader.text()
            info.xdefs[name] = (section, offset)
        elif record == 14:
            reader.u16(); reader.text()
        elif record == 16:
            index = reader.u16()
            reader.u16()
            alignment = reader.u8()
            info.sections[index] = Section(reader.text(), alignment)
        elif record == 18:
            reader.u16(); reader.u32(); reader.text()
        elif record == 20:
            reader.u16(); reader.u8(); reader.text()
        elif record in (22, 24, 26, 42):
            patch_type = reader.u8()
            offset = reader.u16()
            absolute = info.sections[current_section].patch_base + offset
            info.patches.append((current_section, absolute, patch_type))
            skip_patch_expression(reader)
            reader.u16()
        elif record == 28:
            reader.u16(); reader.text()
        elif record == 30:
            reader.u16(); reader.u32(); file_line_defined = True
        elif record == 32:
            if not file_line_defined:
                raise ValueError("line record before file record")
            reader.u32()
        elif record == 34:
            pass
        elif record == 36:
            reader.u8()
        elif record == 38:
            reader.u16()
        elif record == 40:
            reader.u16(); reader.u32(); reader.text()
        elif record == 44:
            reader.u8(); reader.u16()
        elif record == 46:
            reader.u8()
        elif record == 48:
            reader.u16(); reader.u16(); reader.u32(); reader.text()
        elif record in (50, 60):
            reader.u16()
        elif record == 52:
            reader.u16(); reader.u8()
        elif record == 54:
            reader.u16(); reader.u16()
        elif record == 56:
            reader.u16(); reader.u32()
        elif record == 58:
            reader.u16(); reader.u32(); reader.u16()
        elif record in (62, 64, 66, 72):
            patch_type = reader.u8()
            offset = reader.u16()
            absolute = info.sections[current_section].patch_base + offset
            info.patches.append((current_section, absolute, patch_type))
            skip_patch_expression(reader)
            reader.u32()
        elif record in (68, 70):
            pass
        elif record == 74:
            section = reader.u16()
            offset = reader.u32()
            reader.u16(); reader.u32(); reader.u16(); reader.u32()
            reader.u16(); reader.u32(); reader.u32()
            info.functions.append(Function(section, offset, reader.text()))
        elif record == 76:
            info.function_ends.append((reader.u16(), reader.u32()))
            reader.u32()
        elif record in (78, 80):
            reader.u16(); reader.u32(); reader.u32()
        elif record == 82:
            reader.u16(); reader.u32(); reader.u16(); reader.u16()
            reader.u32(); reader.text()
        elif record == 84:
            reader.u16(); reader.u32(); reader.u16(); reader.u16()
            reader.u32()
            for _ in range(reader.u16()):
                reader.u32()
            reader.text(); reader.text()
        else:
            raise ValueError(f"unknown record {record} at 0x{reader.pos - 1:X}")

    return info


def function_bounds(info: ObjectInfo, name: str) -> tuple[int, int, int]:
    starts = [(f.section, f.start) for f in info.functions if f.name == name]
    if not starts and name in info.xdefs:
        starts = [info.xdefs[name]]
    if not starts:
        raise KeyError(name)
    section, start = starts[0]

    ends = sorted(offset for sec, offset in info.function_ends if sec == section and offset > start)
    if ends:
        return section, start, ends[0]

    candidates = [
        offset for sec, offset in info.xdefs.values()
        if sec == section and offset > start
    ]
    candidates.extend(
        f.start for f in info.functions if f.section == section and f.start > start
    )
    end = min(candidates) if candidates else len(info.sections[section].data)
    return section, start, end


def match_function(exe: bytes, body: bytes, masked: set[int]) -> list[int]:
    runs: list[tuple[int, bytes]] = []
    run_start = 0
    for pos in range(len(body) + 1):
        is_masked = pos < len(body) and pos in masked
        if is_masked or pos == len(body):
            if pos - run_start >= 12:
                runs.append((run_start, body[run_start:pos]))
            run_start = pos + 1
    if not runs:
        return []

    anchor_offset, anchor = max(runs, key=lambda item: len(item[1]))
    matches: list[int] = []
    search_from = 0
    while True:
        found = exe.find(anchor, search_from)
        if found < 0:
            break
        candidate = found - anchor_offset
        search_from = found + 1
        if candidate < 0 or candidate + len(body) > len(exe):
            continue
        if all(
            index in masked or exe[candidate + index] == value
            for index, value in enumerate(body)
        ):
            matches.append(candidate)
    return matches


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--obj", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--load-address", type=lambda value: int(value, 0), default=0x8011B000)
    parser.add_argument("--header-size", type=lambda value: int(value, 0), default=0x800)
    parser.add_argument("--json", type=Path)
    parser.add_argument("symbols", nargs="+", help="function names to locate")
    args = parser.parse_args()

    info = parse_object(args.obj)
    exe = args.exe.read_bytes()
    report: dict[str, object] = {
        "object": str(args.obj),
        "executable": str(args.exe),
        "symbols": {},
    }

    for name in args.symbols:
        section, start, end = function_bounds(info, name)
        body = bytes(info.sections[section].data[start:end])
        masked: set[int] = set()
        for patch_section, patch_offset, _ in info.patches:
            if patch_section == section and start <= patch_offset < end:
                relative = patch_offset - start
                masked.update(range(relative, min(relative + 4, len(body))))
        matches = match_function(exe, body, masked)
        addresses = [args.load_address + offset - args.header_size for offset in matches]
        entry = {
            "section": section,
            "object_offset": start,
            "size": len(body),
            "masked_bytes": len(masked),
            "file_offsets": matches,
            "addresses": addresses,
        }
        report["symbols"][name] = entry
        addr_text = ", ".join(f"0x{address:08X}" for address in addresses) or "not found"
        print(f"{name}: size=0x{len(body):X}, masked={len(masked)}, matches={addr_text}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
