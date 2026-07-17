import json
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

PUBLIC_EXPONENT = 3


def rsavp1(signature: bytes, n: int, e: int) -> bytes:
    m = int.from_bytes(signature, byteorder="big")
    m = pow(m, e, n)

    k = (n.bit_length() + 7) // 8
    em = m.to_bytes(k, byteorder="big")

    return em


def vulnPkcs1Check(em: bytes, expected_hash: bytes) -> bool:
    # PKCS#1 v1.5 signature: 0x00 0x01 0xFF...0xFF 0x00 hash

    first_byte = em[0]
    second_byte = em[1]
    third_byte = em[2]

    starts_ok = first_byte == 0x00 and second_byte == 0x01 and third_byte == 0xFF
    if not starts_ok:
        return False

    # Vulnérabilité ici: on vérifie seulement que 0x00 et le hash sont 
    # présents après le bloc de départ, mais pas leurs positions exactes
    zero_index = em.find(b"\x00", 3)
    if zero_index == -1:
        return False

    hash_index = em.find(expected_hash, zero_index + 1)
    return hash_index != -1

def strictPkcs1Check(em: bytes, expected_hash: bytes) -> bool:
    k = len(em)
    h_len = len(expected_hash)

    if k < 3 + h_len + 1:
        return False

    if em[0] != 0x00 or em[1] != 0x01:
        return False

    padding_len = k - 3 - h_len
    if any(byte != 0xFF for byte in em[2 : 2 + padding_len]):
        return False

    separator_index = 2 + padding_len
    if em[separator_index] != 0x00:
        return False

    return em[separator_index + 1 :] == expected_hash


def save_keypair_to_file(file_path: str, key: RSA.RsaKey) -> None:
    data = {"n": str(key.n), "e": key.e, "d": str(key.d)}
    Path(file_path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_keypair_from_file(file_path: str) -> tuple[int, int, int]:
    data = json.loads(Path(file_path).read_text(encoding="utf-8"))
    return int(data["n"]), int(data["e"]), int(data["d"])


def sign_message(message: bytes, n: int, d: int) -> bytes:
    expected_hash = SHA256.new(message).digest()
    k = (n.bit_length() + 7) // 8

    prefix = b"\x00\x01\xff"
    suffix = b"\x00" + expected_hash
    middle_len = k - len(prefix) - len(suffix)

    em = prefix + (b"\xff" * middle_len) + suffix
    m = int.from_bytes(em, byteorder="big")

    signature_int = pow(m, d, n)
    return signature_int.to_bytes(k, byteorder="big")


def verify_signature_vulnerable(
    message: bytes,
    signature: bytes,
    n: int,
    e: int = PUBLIC_EXPONENT,
) -> bool:
    expected_hash = SHA256.new(message).digest()
    em = rsavp1(signature, n, e)

    return vulnPkcs1Check(em, expected_hash)

def verify_signature_strict(
    message: bytes,
    signature: bytes,
    n: int,
    e: int = PUBLIC_EXPONENT,
) -> bool:
    expected_hash = SHA256.new(message).digest()
    em = rsavp1(signature, n, e)

    return strictPkcs1Check(em, expected_hash)

def main(
    message: str = "message",
    key_file: str = "rsa_key.json",
) -> None:

    message_bytes = message.encode()

    key_path = Path(key_file)
    if key_path.exists():
        n, e, d = load_keypair_from_file(key_file)
    else:
        key = RSA.generate(2048, e=PUBLIC_EXPONENT)
        n, e, d = key.n, key.e, key.d
        save_keypair_to_file(key_file, key)
        print(f"Clé RSA générée avec e={PUBLIC_EXPONENT} dans {key_file}")

    signature = sign_message(message_bytes, n, d)

    ok = verify_signature_vulnerable(message_bytes, signature, n, e)
    print("Signature acceptée:", ok)


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
