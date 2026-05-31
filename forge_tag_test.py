import sys
import zlib

sys.path.insert(0, ".deps")

import dns.resolver
from Crypto.Util.number import inverse

import dhcppp


DHCP_MAC = bytes.fromhex("1b 7d 6f 49 37 c9")
FLAG_MAC = bytes.fromhex("53 79 82 b5 97 eb")
CLIENT_MAC = bytes.fromhex("00 00 00 00 00 00")
LEASE_POOL_SIZE = 62
P = 2**130 - 5


def request_lease(dhcp, dev_name):
    request = CLIENT_MAC + DHCP_MAC + b"\x01" + dev_name
    return dhcp.process_pkt(request)


def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")


def build_plaintext(ip, dns1, dns2, dev_name):
    return (
        bytes([int(part) for part in ip.split(".")])
        + bytes([192, 168, 1, 1])
        + bytes([255, 255, 255, 0])
        + bytes([int(part) for part in dns1.split(".")])
        + bytes([int(part) for part in dns2.split(".")])
        + dev_name
        + b"\x00"
    )


def extract(response):
    msg = response[12:]
    encrypted_body = msg[1:-4]
    ciphertext = encrypted_body[:-28]
    tag = encrypted_body[-28:-12]
    nonce = encrypted_body[-12:]
    return ciphertext, tag, nonce


def poly1305_blocks(ciphertext):
    mac_data = ciphertext + bytes.fromhex("000000000000000000002e00000000000000")
    blocks = []
    for i in range(0, len(mac_data), 16):
        block = mac_data[i : i + 16] + b"\x01"
        blocks.append(int.from_bytes(block, byteorder="little"))
    return blocks


def poly1305_tag(ciphertext, r, s):
    acc = 0
    for block in poly1305_blocks(ciphertext):
        acc += block
        acc = (r * acc) % P
    return (acc + s) % (2**128)


def recover_and_forge(pair1, pair2, target_plaintext):
    plaintext1, ciphertext1, tag1 = pair1
    plaintext2, ciphertext2, tag2 = pair2

    tag1_int = int.from_bytes(tag1, byteorder="little")
    tag2_int = int.from_bytes(tag2, byteorder="little")
    keystream = bytes(a ^ b for a, b in zip(ciphertext1, plaintext1))
    target_ciphertext = bytes(a ^ b for a, b in zip(target_plaintext, keystream))

    block_delta = poly1305_blocks(ciphertext2)[2] - poly1305_blocks(ciphertext1)[2]

    for carry1 in range(5):
        for carry2 in range(5):
            expanded_tag1 = tag1_int + carry1 * 2**128
            expanded_tag2 = tag2_int + carry2 * 2**128
            tag_delta = expanded_tag2 - expanded_tag1

            base = (tag_delta * inverse(block_delta, P)) % P
            root = pow(base, (P + 1) // 4, P)

            for candidate in (root, (-root) % P):
                if candidate != 1 and candidate & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF == candidate:
                    r = candidate
                    s = (tag1_int - poly1305_tag(ciphertext1, r, 0)) % (2**128)
                    forged_tag_int = poly1305_tag(target_ciphertext, r, s)
                    forged_tag = forged_tag_int.to_bytes(16, "little")
                    return r, s, target_ciphertext, forged_tag

    raise RuntimeError("could not recover Poly1305 parameters")


def make_flagserver():
    flagserver = dhcppp.FlagServer.__new__(dhcppp.FlagServer)
    flagserver.mac = FLAG_MAC
    flagserver.dns = dns.resolver.Resolver()
    return flagserver


def main():
    dhcppp.TIMEOUT = 0.001
    dhcp = dhcppp.DHCPServer()

    for i in range(LEASE_POOL_SIZE - 1):
        request_lease(dhcp, b"filler_a_" + str(i).encode())

    dev1 = b"AAAAAAAAAAAAAAAAAAAAAAAAA"
    response1 = request_lease(dhcp, dev1)

    for i in range(LEASE_POOL_SIZE - 1):
        request_lease(dhcp, b"filler_b_" + str(i).encode())

    dev2 = b"AAAAAAAAAAAAAAAAAAAAAAAAB"
    response2 = request_lease(dhcp, dev2)

    plaintext1 = build_plaintext("192.168.1.2", "8.8.8.8", "8.8.4.4", dev1)
    plaintext2 = build_plaintext("192.168.1.2", "8.8.8.8", "8.8.4.4", dev2)
    target_plaintext = build_plaintext("192.168.1.2", "1.1.1.1", "1.1.1.1", dev2)

    ciphertext1, tag1, nonce1 = extract(response1)
    ciphertext2, tag2, nonce2 = extract(response2)

    r, s, forged_ciphertext, forged_tag = recover_and_forge(
        (plaintext1, ciphertext1, tag1),
        (plaintext2, ciphertext2, tag2),
        target_plaintext,
    )

    forged_body = forged_ciphertext + forged_tag + nonce1
    decrypted = dhcppp.decrypt_msg(forged_body)
    forged_lease = b"\x02" + forged_body + calc_crc(target_plaintext)
    flagserver_pkt = CLIENT_MAC + FLAG_MAC + forged_lease

    flagserver = make_flagserver()
    accepted = False
    try:
        flagserver.process_pkt(flagserver_pkt)
        accepted = flagserver.dns1 == "1.1.1.1" and flagserver.dns2 == "1.1.1.1"
    except Exception as exc:
        print("flagserver_error =", repr(exc))

    print("same_nonce =", nonce1 == nonce2)
    print("recovered_r =", hex(r))
    print("recovered_s =", hex(s))
    print("target_dns =", "1.1.1.1")
    print("forged_tag =", forged_tag.hex())
    print("decrypt_matches_target =", decrypted == target_plaintext)
    print("crc_matches_target =", calc_crc(target_plaintext).hex())
    print("flagserver_accepts_forged_lease =", accepted)


if __name__ == "__main__":
    main()
