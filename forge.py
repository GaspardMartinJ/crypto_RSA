import gmpy2
from Crypto.Hash import SHA256
from verificateur_vulnerable import (
    PUBLIC_EXPONENT,
    load_keypair_from_file,
    verify_signature_vulnerable,
    verify_signature_strict
)

def build_lower_bound_block(
    message_bytes: bytes, k: int
) -> tuple[int, int]:
    h = SHA256.new(message_bytes).digest()
    # Le bloc minimal qui passe la vérification
    fixed = b"\x00\x01\xFF" + b"\x00" + h
    garbage_len = k - len(fixed)
    # On remplit reste de 0
    b_low = int.from_bytes(fixed, byteorder="big") << (garbage_len * 8)
    return b_low, garbage_len * 8

def forge_signature(
    message: bytes,
    n: int,
    e: int = PUBLIC_EXPONENT,
) -> bytes:
    # 256 dans le cas d'une une clé RSA de 2048 bits
    k = (n.bit_length() + 7) // 8
    b_low, garbage_bits = build_lower_bound_block(message, k)

    s, is_exact = gmpy2.iroot(b_low, e)
    if not is_exact:
        s += 1
        
    cube = s**e

    # Si le cube de la signature est plus grand que le modulo, la structure de
    # la signature est perdue pendant la vérification (m = pow(m, e, n))
    if cube >= n:
        raise RuntimeError("Le cube forgé dépasse le modulo: clé trop petite")
    
    # Si le "bruit" (différence entre le cube trouvé et le bloc valide minimal) est 
    # plus grand que la fenêtre de bit non vérifiée par le vérificateur, on aura une 
    # "retenue" sur des bits réelement vérifiés donc la vérification ne passera pas
    if cube - b_low >= 2**garbage_bits:
        raise RuntimeError("L'erreur d'arrondi dépasse la fenêtre de garbage")

    return s.to_bytes(k, byteorder="big")

def main() -> None:
    n, e, _ = load_keypair_from_file("rsa_key.json")

    message = "Salut c'est alice, transfère moi 1000€"
    message_bytes = message.encode()

    forged_signature = forge_signature(message_bytes, n, e)
    print("Signature forgée (hex):", forged_signature.hex())

    ok = verify_signature_vulnerable(message_bytes, forged_signature, n, e)
    print("Le vérificateur vulnérable accepte la signature forgée:", ok)
    
    ok_strict = verify_signature_strict(message_bytes, forged_signature, n, e)
    print("Le vérificateur strict accepte la signature forgée:", ok_strict)

if __name__ == "__main__":
    main()