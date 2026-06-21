from pathlib import Path
import struct, zlib
p = Path('tasks/CVE-2016-5314_libtiff/seeds/poc.tiff')
if not p.exists():
    print('file not found', p)
    raise SystemExit(1)

b = p.read_bytes()
cnt = struct.unpack_from('<H', b, 8)[0]
print('len', len(b))
print('header', b[:8].hex())
print('ifd_count', cnt)
for i in range(cnt):
    off = 8 + 2 + i*12
    tag, dtype, count, val = struct.unpack_from('<HHII', b, off)
    print(i, hex(tag), dtype, count, val)

# get strip offset/count
strip_off = None
strip_cnt = None
for i in range(cnt):
    off = 8 + 2 + i*12
    tag = struct.unpack_from('<H', b, off)[0]
    if tag == 273:
        strip_off = struct.unpack_from('<I', b, off+8)[0]
    if tag == 279:
        strip_cnt = struct.unpack_from('<I', b, off+8)[0]

print('strip_off', strip_off, 'strip_cnt', strip_cnt)
comp = b[strip_off:strip_off+strip_cnt]
print('compressed len', len(comp))
try:
    dec = zlib.decompress(comp)
    print('decompressed len', len(dec))
except Exception as e:
    print('decompress error:', e)

expected_uncompressed = None
# compute expected per-strip uncompressed from tags
for i in range(cnt):
    off = 8 + 2 + i*12
    tag, dtype, count, val = struct.unpack_from('<HHII', b, off)
    if tag == 256:
        width = val
    if tag == 278:
        rows_per_strip = val
    if tag == 277:
        spp = val
    if tag == 258:
        bps = val
expected_uncompressed = width * rows_per_strip * spp * (bps//8)
print('expected (from tags) uncompressed bytes per strip (based on BitsPerSample)=', expected_uncompressed)
print('note: to trigger overflow the decompressed len must be larger than expected_uncompressed')
