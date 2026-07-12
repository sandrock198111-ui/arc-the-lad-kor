from __future__ import annotations

import argparse
import ctypes
from pathlib import Path


def decompress(source: Path) -> bytes:
    raw = source.read_bytes()
    frame_offset = raw.rfind(b"\x28\xb5\x2f\xfd")
    if frame_offset < 0:
        raise RuntimeError("DuckStation save state has no Zstandard frame")
    compressed = raw[frame_offset:]
    try:
        import zstandard
    except ModuleNotFoundError:
        dll_path = (
            Path.home()
            / ".cache"
            / "codex-runtimes"
            / "codex-primary-runtime"
            / "dependencies"
            / "native"
            / "poppler"
            / "Library"
            / "bin"
            / "zstd.dll"
        )
        library = ctypes.WinDLL(str(dll_path))
        library.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
        library.ZSTD_decompress.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.ZSTD_decompress.restype = ctypes.c_size_t
        library.ZSTD_isError.argtypes = [ctypes.c_size_t]
        library.ZSTD_isError.restype = ctypes.c_uint

        content_size = library.ZSTD_getFrameContentSize(compressed, len(compressed))
        if content_size >= 0xFFFFFFFFFFFFFFFE:
            content_size = 16 * 1024 * 1024
        output = ctypes.create_string_buffer(content_size)
        written = library.ZSTD_decompress(
            output, content_size, compressed, len(compressed)
        )
        if library.ZSTD_isError(written):
            raise RuntimeError("Zstandard decompression failed")
        return output.raw[:written]

    return zstandard.ZstdDecompressor().decompress(
        compressed, max_output_size=16 * 1024 * 1024
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decompress a DuckStation Zstandard save state for read-only analysis."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(decompress(args.source))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
