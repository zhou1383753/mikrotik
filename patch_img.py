import sys
import struct
import lzma

# RouterOS 7.x x86 install-image contains a FAT16 filesystem.
# The LINUX kernel is a PE image with an embedded XZ-compressed vmlinux.
# The public keys are inside the compressed initramfs, so a raw byte
# replacement against the whole .img file cannot find them.

MIKRO_NPK_PUBLIC_KEY = bytes.fromhex(
    "C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59"
)
CUSTOM_NPK_PUBLIC_KEY = bytes.fromhex(
    "9BA63F05E55C293AFA9D961F9C43675D990252A158358986F5BB699700014709"
)
MIKRO_LICENSE_PUBLIC_KEY = bytes.fromhex(
    "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
)
CUSTOM_LICENSE_PUBLIC_KEY = bytes.fromhex(
    "52AC2A5C0DC7D1405E96EA6965A17BAA13C2A6EA010A567B9216A3A6F7970462"
)

KEYS = {
    MIKRO_NPK_PUBLIC_KEY: CUSTOM_NPK_PUBLIC_KEY,
    MIKRO_LICENSE_PUBLIC_KEY: CUSTOM_LICENSE_PUBLIC_KEY,
}


def find_xz_payload(kernel):
    xz_start = b"\xFD7zXZ\x00\x00\x01"
    xz_end = b"\x00\x00\x00\x00\x01\x59\x5A"

    start = 0
    tmp = kernel
    while xz_start in tmp:
        start += tmp.index(xz_start) + 8
        tmp = kernel[start:]
    start -= 8

    end = 0
    tmp = kernel
    while xz_end in tmp:
        end += tmp.index(xz_end) + 7
        tmp = kernel[end:]

    if start < 0 or end <= start:
        raise ValueError("Embedded XZ payload not found in RouterOS LINUX kernel")

    return start, end


def patch_kernel(kernel):
    if kernel[:2] != b"MZ":
        raise ValueError("LINUX file is not a PE kernel")

    xz_start, xz_end = find_xz_payload(kernel)
    old_xz = kernel[xz_start:xz_end]
    vmlinux = lzma.decompress(old_xz)

    cpio_magic = b"07070100"
    cpio_footer = b"TRAILER!!!\x00\x00\x00\x00"
    cpio_start = vmlinux.find(cpio_magic)
    if cpio_start < 0:
        raise ValueError("RouterOS initramfs CPIO header not found")

    footer_pos = vmlinux.find(cpio_footer, cpio_start)
    if footer_pos < 0:
        raise ValueError("RouterOS initramfs CPIO footer not found")

    cpio_end = footer_pos + len(cpio_footer)
    initramfs = vmlinux[cpio_start:cpio_end]
    patched_initramfs = initramfs
    total = 0

    for old_key, new_key in KEYS.items():
        count = patched_initramfs.count(old_key)
        if count:
            print(
                f"[+] Found {count} occurrence(s) of public key "
                f"{old_key[:8].hex().upper()}..."
            )
            patched_initramfs = patched_initramfs.replace(old_key, new_key)
            total += count

    if total == 0:
        raise ValueError(
            "No supported MikroTik public key found inside RouterOS initramfs"
        )

    new_vmlinux = vmlinux.replace(initramfs, patched_initramfs)

    # Match the RouterOS 7.x patch_bzimage compression parameters.
    new_xz = lzma.compress(
        new_vmlinux,
        check=lzma.CHECK_CRC32,
        filters=[
            {"id": lzma.FILTER_X86},
            {
                "id": lzma.FILTER_LZMA2,
                "preset": 9 | lzma.PRESET_EXTREME,
                "dict_size": 32 * 1024 * 1024,
                "lc": 4,
                "lp": 0,
                "pb": 0,
            },
        ],
    )

    if len(new_xz) > len(old_xz):
        raise ValueError(
            f"Patched kernel is too large: {len(new_xz)} > {len(old_xz)} bytes"
        )

    new_xz = new_xz.ljust(len(old_xz), b"\x00")
    return kernel[:xz_start] + new_xz + kernel[xz_end:], total


def patch_fat16_image(path):
    print(f"[*] Reading image: {path}")
    with open(path, "rb") as f:
        image = bytearray(f.read())

    bps = struct.unpack_from("<H", image, 11)[0]
    spc = image[13]
    reserved = struct.unpack_from("<H", image, 14)[0]
    nfats = image[16]
    root_entries = struct.unpack_from("<H", image, 17)[0]
    spf = struct.unpack_from("<H", image, 22)[0]

    if bps != 512 or spc == 0 or nfats == 0 or spf == 0:
        raise ValueError("Unsupported filesystem layout; expected FAT16 RouterOS image")

    root_sectors = (root_entries * 32 + bps - 1) // bps
    fat_start = reserved * bps
    root_start = (reserved + nfats * spf) * bps
    data_start = (reserved + nfats * spf + root_sectors) * bps
    fat = image[fat_start:fat_start + spf * bps]

    def next_cluster(cluster):
        return struct.unpack_from("<H", fat, cluster * 2)[0]

    def cluster_chain(start_cluster):
        chain = []
        cluster = start_cluster
        seen = set()
        while 2 <= cluster < 0xFFF8:
            if cluster in seen:
                raise ValueError("FAT cluster chain loop detected")
            seen.add(cluster)
            chain.append(cluster)
            cluster = next_cluster(cluster)
        return chain

    entry = None
    for i in range(root_entries):
        off = root_start + i * 32
        ent = image[off:off + 32]
        if ent[0] in (0x00, 0xE5):
            continue
        if ent[:11] == b"LINUX      ":
            entry = ent
            break

    if entry is None:
        raise ValueError("LINUX file not found in install image")

    start_cluster = struct.unpack_from("<H", entry, 26)[0]
    file_size = struct.unpack_from("<I", entry, 28)[0]
    clusters = cluster_chain(start_cluster)
    cluster_size = spc * bps
    capacity = len(clusters) * cluster_size

    if file_size > capacity:
        raise ValueError("LINUX file size exceeds FAT cluster-chain capacity")

    kernel = b"".join(
        image[data_start + (c - 2) * cluster_size:
              data_start + (c - 1) * cluster_size]
        for c in clusters
    )[:file_size]

    print(f"[*] LINUX kernel size: {file_size} bytes")
    patched_kernel, count = patch_kernel(kernel)

    # Keep the FAT file size and cluster chain unchanged.
    padded = patched_kernel.ljust(len(clusters) * cluster_size, b"\x00")
    for index, cluster in enumerate(clusters):
        begin = index * cluster_size
        end = begin + cluster_size
        disk_offset = data_start + (cluster - 2) * cluster_size
        image[disk_offset:disk_offset + cluster_size] = padded[begin:end]

    with open(path, "wb") as f:
        f.write(image)

    # Mandatory post-patch verification.
    xz_start, xz_end = find_xz_payload(patched_kernel)
    verify_vmlinux = lzma.decompress(patched_kernel[xz_start:xz_end])

    remaining = sum(verify_vmlinux.count(key) for key in KEYS)
    custom_count = (
        verify_vmlinux.count(CUSTOM_NPK_PUBLIC_KEY)
        + verify_vmlinux.count(CUSTOM_LICENSE_PUBLIC_KEY)
    )

    if remaining:
        raise ValueError(
            f"Verification failed: {remaining} official public key(s) remain"
        )
    if custom_count == 0:
        raise ValueError("Verification failed: custom public key was not found")

    print(f"[+] Patched {count} public-key occurrence(s)")
    print(f"[+] Verification OK: {custom_count} custom public-key occurrence(s) present")
    print(f"[+] Successfully patched {path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 patch_img.py <install-image.img>")
        sys.exit(1)

    try:
        patch_fat16_image(sys.argv[1])
    except Exception as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)
