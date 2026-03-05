from binascii import unhexlify
from Crypto.Cipher import DES, DES3

BDK_HEX = "39ede3a9437f3ff561898d1f6fabbd25"
KSN_HEX = "729C77361E9A51E000F2"
CIPHERTEXT_HEX = "FCC832A91953151148E86A01BE9420AC"

KEY_MASK_HEX = "C0C0C0C000000000C0C0C0C000000000"

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def des_encrypt(key8: bytes, data8: bytes) -> bytes:
    return DES.new(key8, DES.MODE_ECB).encrypt(data8)

def tdes_encrypt_2key(key16: bytes, data8: bytes) -> bytes:
    # 2-key 3DES: K1||K2||K1
    k24 = key16 + key16[:8]
    k24 = DES3.adjust_key_parity(k24)
    return DES3.new(k24, DES3.MODE_ECB).encrypt(data8)

def tdes_decrypt_2key_ecb(key16: bytes, data: bytes) -> bytes:
    k24 = key16 + key16[:8]
    k24 = DES3.adjust_key_parity(k24)
    return DES3.new(k24, DES3.MODE_ECB).decrypt(data)

def ksn_with_counter_zeroed(ksn10: bytes) -> bytes:
    # Zero out the rightmost 21 bits (transaction counter)
    ksn_int = int.from_bytes(ksn10, "big")
    ksn_int &= ~((1 << 21) - 1)
    return ksn_int.to_bytes(10, "big")

def get_counter(ksn10: bytes) -> int:
    return int.from_bytes(ksn10, "big") & ((1 << 21) - 1)

def nrkgp(cur_key16: bytes, ksn_reg10: bytes) -> bytes:
    """
    Non-Reversible Key Generation Process (DUKPT TDES).
    """
    mask = unhexlify(KEY_MASK_HEX)
    data = ksn_reg10[2:10]  # rightmost 8 bytes of KSN

    # Right half (using current key)
    key_l = cur_key16[:8]
    key_r = cur_key16[8:16]
    i = xor_bytes(data, key_r)
    i = des_encrypt(key_l, i)
    i = xor_bytes(i, key_r)
    new_r = i

    # Left half (using masked key)
    k2 = xor_bytes(cur_key16, mask)
    key_l2 = k2[:8]
    key_r2 = k2[8:16]
    i2 = xor_bytes(data, key_r2)
    i2 = des_encrypt(key_l2, i2)
    i2 = xor_bytes(i2, key_r2)
    new_l = i2

    return new_l + new_r

def derive_ipek(bdk16: bytes, ksn10: bytes) -> bytes:
    ksn0 = ksn_with_counter_zeroed(ksn10)
    ksn8 = ksn0[:8]

    mask = unhexlify(KEY_MASK_HEX)
    left = tdes_encrypt_2key(bdk16, ksn8)
    right = tdes_encrypt_2key(xor_bytes(bdk16, mask), ksn8)

    return left + right

def derive_future_key(bdk16: bytes, ksn10: bytes) -> bytes:
    ipek = derive_ipek(bdk16, ksn10)

    counter = get_counter(ksn10)
    ksn_reg = bytearray(ksn_with_counter_zeroed(ksn10))

    cur = ipek
    # Iterate bits from MSB to LSB of the 21-bit counter
    for bit in range(20, -1, -1):
        if counter & (1 << bit):
            ksn_reg_int = int.from_bytes(ksn_reg, "big")
            ksn_reg_int |= (1 << bit)
            ksn_reg[:] = ksn_reg_int.to_bytes(10, "big")
            cur = nrkgp(cur, bytes(ksn_reg))

    return cur

def main():
    bdk = unhexlify(BDK_HEX)
    ksn = unhexlify(KSN_HEX)
    ct = unhexlify(CIPHERTEXT_HEX)

    future_key = derive_future_key(bdk, ksn)

    print("BDK:", bdk.hex().upper())
    print("KSN:", ksn.hex().upper())
    print("Future Key (16B):", future_key.hex().upper())

    pt = tdes_decrypt_2key_ecb(future_key, ct)

    print("Plaintext HEX:", pt.hex().upper())
    try:
        print("Plaintext ASCII:", pt.decode("utf-8"))
    except:
        print("Plaintext ASCII: (no es UTF-8 limpio)")

if __name__ == "__main__":
    main()