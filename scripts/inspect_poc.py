from pathlib import Path
import struct
p = Path('tasks/CVE-2016-5314_libtiff/seeds/poc.tiff')
if not p.exists():
    print('file not found:', p)
    raise SystemExit(1)
b = p.read_bytes()
print('len', len(b))
print('header', b[:8].hex())
try:
    cnt = struct.unpack_from('<H', b, 8)[0]
except Exception as e:
    print('failed to read ifd count:', e)
    raise
print('ifd_count', cnt)
for i in range(cnt):
    off = 8 + 2 + i*12
    tag, dtype, count, val = struct.unpack_from('<HHII', b, off)
    print(i, hex(tag), dtype, count, val)
# show next-ifd pointer
next_ifd = struct.unpack_from('<I', b, 8 + 2 + cnt*12)[0]
print('next_ifd', next_ifd)
# show strip offsets and bytecounts (first values)
# find entries for tag 273 and 279 in the printed list above
for tag_to_check in (273, 279):
    for i in range(cnt):
        off = 8 + 2 + i*12
        tag = struct.unpack_from('<H', b, off)[0]
        if tag == tag_to_check:
            val = struct.unpack_from('<I', b, off+8)[0]
            print('tag', tag_to_check, 'points to', val)
            break
