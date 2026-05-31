import sys

sys.path.insert(0, ".deps")

import dhcppp


DHCP_MAC = bytes.fromhex("1b 7d 6f 49 37 c9")
CLIENT_MAC = bytes.fromhex("00 00 00 00 00 00")
LEASE_POOL_SIZE = 62


def request_lease(dhcp, dev_name):
    request = CLIENT_MAC + DHCP_MAC + b"\x01" + dev_name
    return dhcp.process_pkt(request)


def extract_encrypted_fields(response):
    msg = response[12:]
    encrypted_body = msg[1:-4]
    ciphertext = encrypted_body[:-28]
    tag = encrypted_body[-28:-12]
    nonce = encrypted_body[-12:]
    crc = msg[-4:]
    return ciphertext, tag, nonce, crc


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


def main():
    dhcppp.TIMEOUT = 0.001
    dhcp = dhcppp.DHCPServer()

    # Exhaust the pool once. The initial rngserver_0 lease is then recycled,
    # so later entropy depends only on the stable RNG_INIT value.
    for i in range(LEASE_POOL_SIZE - 1):
        request_lease(dhcp, b"filler_a_" + str(i).encode())

    dev1 = b"AAAAAAAAAAAAAAAAAAAAAAAAA"
    response1 = request_lease(dhcp, dev1)

    # Rotate the pool until the same IP is assigned again.
    for i in range(LEASE_POOL_SIZE - 1):
        request_lease(dhcp, b"filler_b_" + str(i).encode())

    dev2 = b"AAAAAAAAAAAAAAAAAAAAAAAAB"
    response2 = request_lease(dhcp, dev2)

    ct1, tag1, nonce1, crc1 = extract_encrypted_fields(response1)
    ct2, tag2, nonce2, crc2 = extract_encrypted_fields(response2)

    pt1 = build_plaintext("192.168.1.2", dev1)
    pt2 = build_plaintext("192.168.1.2", dev2)

    print("pt1_first32 =", pt1[:32].hex())
    print("pt2_first32 =", pt2[:32].hex())
    print("same_first32 =", pt1[:32] == pt2[:32])
    print("ct1 =", ct1.hex())
    print("tag1 =", tag1.hex())
    print("nonce1 =", nonce1.hex())
    print("crc1 =", crc1.hex())
    print("ct2 =", ct2.hex())
    print("tag2 =", tag2.hex())
    print("nonce2 =", nonce2.hex())
    print("crc2 =", crc2.hex())
    print("same_nonce =", nonce1 == nonce2)
    print("same_tag =", tag1 == tag2)
    print("same_ciphertext =", ct1 == ct2)


if __name__ == "__main__":
    main()
