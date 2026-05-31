import sys

sys.path.insert(0, ".deps")

from Crypto.Cipher import ChaCha20_Poly1305

import dhcppp


def build_plaintext(ip, dev_name):
    return (
        bytes([int(part) for part in ip.split(".")])
        + bytes([192, 168, 1, 1])
        + bytes([255, 255, 255, 0])
        + bytes([8, 8, 8, 8])
        + bytes([8, 8, 4, 4])
        + dev_name
        + b"\x00"
    )


def vulnerable_nonce(msg, entropy):
    return dhcppp.sha256(msg[:32] + entropy[:32])[:12]


def counter_nonce(counter):
    return counter.to_bytes(12, "little")


def encrypt_with_nonce(msg, nonce):
    cipher = ChaCha20_Poly1305.new(key=dhcppp.CHACHA_KEY, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    return ciphertext, tag


def main():
    entropy = dhcppp.RNG_INIT[:32]

    pt1 = build_plaintext("192.168.1.2", b"AAAAAAAAAAAAAAAAAAAAAAAAA")
    pt2 = build_plaintext("192.168.1.2", b"AAAAAAAAAAAAAAAAAAAAAAAAB")

    bad_nonce1 = vulnerable_nonce(pt1, entropy)
    bad_nonce2 = vulnerable_nonce(pt2, entropy)

    fixed_nonce1 = counter_nonce(0)
    fixed_nonce2 = counter_nonce(1)

    bad_ct1, bad_tag1 = encrypt_with_nonce(pt1, bad_nonce1)
    bad_ct2, bad_tag2 = encrypt_with_nonce(pt2, bad_nonce2)
    fixed_ct1, fixed_tag1 = encrypt_with_nonce(pt1, fixed_nonce1)
    fixed_ct2, fixed_tag2 = encrypt_with_nonce(pt2, fixed_nonce2)

    print("same_first32 =", pt1[:32] == pt2[:32])
    print("bad_nonce1 =", bad_nonce1.hex())
    print("bad_nonce2 =", bad_nonce2.hex())
    print("bad_same_nonce =", bad_nonce1 == bad_nonce2)
    print("bad_same_keystream_prefix =", bytes(a ^ b for a, b in zip(bad_ct1, bad_ct2))[:32] == bytes(a ^ b for a, b in zip(pt1, pt2))[:32])
    print("fixed_nonce1 =", fixed_nonce1.hex())
    print("fixed_nonce2 =", fixed_nonce2.hex())
    print("fixed_same_nonce =", fixed_nonce1 == fixed_nonce2)
    print("fixed_same_keystream_prefix =", bytes(a ^ b for a, b in zip(fixed_ct1, fixed_ct2))[:32] == bytes(a ^ b for a, b in zip(pt1, pt2))[:32])
    print("bad_tag1 =", bad_tag1.hex())
    print("bad_tag2 =", bad_tag2.hex())
    print("fixed_tag1 =", fixed_tag1.hex())
    print("fixed_tag2 =", fixed_tag2.hex())


if __name__ == "__main__":
    main()
