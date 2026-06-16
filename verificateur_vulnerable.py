from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def rsavp1(signature: bytes, n: int, e: int) -> bytes:
    m = int.from_bytes(signature, byteorder="big")
    m = pow(m, e, n)

    k = (n.bit_length() + 7) // 8
    em = m.to_bytes(k, byteorder="big")

    return em


def vulnPkcs1Check(em: bytes, expected_hash: bytes) -> bool:
    # PKCS#1 v1.5 signature: 0x00 0x01 0xFF...0x00 hash

    first_byte = em[0]
    second_byte = em[1]
    third_byte = em[2]

    starts_ok = first_byte == 0x00 and second_byte == 0x01 and third_byte == 0xFF

    ends_ok = em[-len(expected_hash) - 1 :] == bytes([0x00]) + expected_hash

    return starts_ok and ends_ok


PUBLIC_EXPONENT = 3


def generate_public_key_2048(e: int = PUBLIC_EXPONENT) -> tuple[int, int]:
    """Generate a 2048-bit RSA key in memory and return (n, e)."""
    key = RSA.generate(2048, e=e)
    pub = key.publickey()
    return pub.n, pub.e


def verify_signature_vulnerable(
    message: bytes,
    signature: bytes,
    n: int,
    e: int = PUBLIC_EXPONENT,
) -> bool:
    expected_hash = SHA256.new(message).digest()
    em = rsavp1(signature, n, e)

    return vulnPkcs1Check(em, expected_hash)


def main(
    message: str = "message",
    signature_hex: str = "0001",
) -> None:

    message_bytes = message.encode()

    n, e = generate_public_key_2048()
    signature = bytes.fromhex(signature_hex)

    ok = verify_signature_vulnerable(message_bytes, signature, n, e)
    print("Signature acceptee:", ok)


if __name__ == "__main__":
    main()



# def vulnPkcs1Check1(em: bytes, expected_hash: bytes) -> bool:
#     # PKCS#1 v1.5 signature: 0x00 0x01 0xFF...0x00 hash

#     first_byte = em[0]
#     second_byte = em[1]
#     third_byte = em[2]

#     starts_ok = first_byte == 0x00 and second_byte == 0x01 and third_byte == 0xFF
#     if not starts_ok:
#         return False

#     stop_index = 3
#     for bytes in em[3:]:
#         if bytes == 0x00:
#             stop_index = em.index(bytes)
#             break

#     for i in range(stop_index + 1, len(em)):
#         if em[i] != expected_hash[i - (stop_index + 1)]:
#             return False

#     return True


# def vulnPkcs1Check2(em: bytes, expected_hash: bytes) -> bool:
#     # PKCS#1 v1.5 signature: 0x00 0x01 0xFF...0x00 hash

#     first_byte = em[0]
#     second_byte = em[1]

#     starts_ok = first_byte == 0x00 and second_byte == 0x01
#     if not starts_ok:
#         return False

#     stop_index = 2
#     for bytes in em[2:]:
#         if bytes == 0x00:
#             stop_index = em.index(bytes)
#             break
#         if bytes != 0xFF:
#             return False

#     for i in range(0, len(expected_hash)):
#         if em[i + stop_index + 1] != expected_hash[i]:
#             return False

#     return True