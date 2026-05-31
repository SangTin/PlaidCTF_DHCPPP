import sys

sys.path.insert(0, ".deps")

import dhcppp


DHCP_MAC = bytes.fromhex("1b 7d 6f 49 37 c9")
CLIENT_MAC = bytes.fromhex("00 00 00 00 00 00")


def parse_lease_response(response):
    msg = response[12:]
    encrypted_body = msg[1:-4]
    ciphertext = encrypted_body[:-28]
    tag = encrypted_body[-28:-12]
    nonce = encrypted_body[-12:]
    crc = msg[-4:]

    return {
        "src_mac": response[:6],
        "dst_mac": response[6:12],
        "option": msg[:1],
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce,
        "crc": crc,
    }


def main():
    dhcp = dhcppp.DHCPServer()
    dev_name = b"test_device"
    request = CLIENT_MAC + DHCP_MAC + b"\x01" + dev_name
    response = dhcp.process_pkt(request)
    fields = parse_lease_response(response)

    print("request_hex =", request.hex())
    print("response_hex =", response.hex())
    print("response_len =", len(response))
    print("src_mac =", fields["src_mac"].hex())
    print("dst_mac =", fields["dst_mac"].hex())
    print("option =", fields["option"].hex())
    print("ciphertext_len =", len(fields["ciphertext"]))
    print("ciphertext =", fields["ciphertext"].hex())
    print("tag =", fields["tag"].hex())
    print("nonce =", fields["nonce"].hex())
    print("crc =", fields["crc"].hex())


if __name__ == "__main__":
    main()
