import sys

# 官方与自定义公钥 (32 bytes Hex)
MIKRO_PUBKEY = bytes.fromhex("C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59")
CUSTOM_PUBKEY = bytes.fromhex("9BA63F05E55C293AFA9D961F9C43675D990252A158358986F5BB699700014709")

def patch_image_file(img_path):
    print(f"[*] Reading image: {img_path}")
    with open(img_path, 'rb') as f:
        data = f.read()

    count = data.count(MIKRO_PUBKEY)
    if count == 0:
        print("[!] Warning: Official MikroTik Public Key not found in IMG! (It may already be patched or uses a non-standard layout)")
        return False

    print(f"[+] Found {count} instance(s) of official public key. Replacing with custom key...")
    patched_data = data.replace(MIKRO_PUBKEY, CUSTOM_PUBKEY)

    with open(img_path, 'wb') as f:
        f.write(patched_data)
    print(f"[+] Successfully patched {img_path}!")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 patch_img.py <install-image.img>")
        sys.exit(1)
    patch_image_file(sys.argv[1])
