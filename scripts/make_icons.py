"""Generate the extension's PNG icons (16/32/48/128) with no dependencies (pure zlib PNG writer).

Design: rounded square in deep blue with a white "eye" outline and a red pupil (watching for hidden text).
Usage: python scripts/make_icons.py  -> extension/icons/icon{16,32,48,128}.png
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"
BG = (47, 91, 211)
FG = (255, 255, 255)
PUPIL = (220, 60, 50)


def _png(w: int, h: int, rows: list[bytes]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + r for r in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _pixel(x: float, y: float) -> tuple[int, int, int, int]:
    """x, y in [0,1]. Returns RGBA."""
    r = 0.22  # corner radius
    cx, cy = min(max(x, r), 1 - r), min(max(y, r), 1 - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r:
        return (0, 0, 0, 0)
    dx, dy = x - 0.5, y - 0.5
    # almond eye: intersection of two circles
    rr, off = 0.42, 0.27
    d1 = math.hypot(dx, dy - off)
    d2 = math.hypot(dx, dy + off)
    inside_eye = d1 < rr and d2 < rr
    outline = inside_eye and (d1 > rr - 0.07 or d2 > rr - 0.07)
    pupil = math.hypot(dx, dy) < 0.11
    if pupil:
        return (*PUPIL, 255)
    if outline or (inside_eye and math.hypot(dx, dy) < 0.17):
        return (*FG, 255)
    return (*BG, 255)


def render(size: int, ss: int = 4) -> bytes:
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    p = _pixel((px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size)
                    a = p[3]
                    acc[0] += p[0] * a
                    acc[1] += p[1] * a
                    acc[2] += p[2] * a
                    acc[3] += a
            n = ss * ss
            alpha = acc[3] / n
            if acc[3]:
                row += bytes((round(acc[0] / acc[3]), round(acc[1] / acc[3]), round(acc[2] / acc[3]), round(alpha)))
            else:
                row += b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    return _png(size, size, rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for s in (16, 32, 48, 128):
        (OUT / f"icon{s}.png").write_bytes(render(s))
    print(f"wrote icons to {OUT}")


if __name__ == "__main__":
    main()
