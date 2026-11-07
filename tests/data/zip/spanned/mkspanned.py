"""Turns a normal (non-ZIP64) zip into a spanned set name.z01, name.z02, ..., name.zip
(disk numbers and per-disk offsets as PKWARE splitting writes them).
usage: mkspanned.py <in.zip> <out dir> <name> <disk size>"""
import struct, sys, os

src, out, name, size = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
z = open(src, "rb").read()
e = z.rfind(b"PK\x05\x06")
(_, disk, cdd, n_disk, n_total, cd_size, cd_off, clen) = struct.unpack("<IHHHHIIH", z[e:e + 22])
assert disk == 0 and n_disk == n_total
data = b"PK\x07\x08" + z[:cd_off]          # split signature, then the local records
chunks = [data[i:i + size] for i in range(0, len(data), size)]
last = len(chunks) - 1

def where(q):  # position in the data stream -> (disk, offset in disk)
    d = min(q // size, last)
    return d, q - d * size

cd = bytearray(z[cd_off:cd_off + cd_size])
i = 0
while i < len(cd):
    assert cd[i:i + 4] == b"PK\x01\x02"
    nl, xl, cl = struct.unpack("<HHH", cd[i + 28:i + 34])
    off = struct.unpack("<I", cd[i + 42:i + 46])[0]
    d, rel = where(off + 4)
    struct.pack_into("<H", cd, i + 34, d)
    struct.pack_into("<I", cd, i + 42, rel)
    i += 46 + nl + xl + cl
cd_rel = len(chunks[last])
eocd = struct.pack("<IHHHHIIH", 0x06054b50, last, last, n_total, n_total, cd_size, cd_rel, 0)
os.makedirs(out, exist_ok=True)
for k, c in enumerate(chunks):
    fn = f"{name}.zip" if k == last else f"{name}.z{k + 1:02d}"
    body = c + bytes(cd) + eocd if k == last else c
    open(os.path.join(out, fn), "wb").write(body)
    print(fn, len(body))
