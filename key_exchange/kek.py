"""
kek.py — Operaciones criptográficas sobre KEK, PEK y BDK.

Todas las funciones que manejan material de clave trabajan exclusivamente
con bytes; la conversión hex↔bytes ocurre en los bordes (CLI / I/O).
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES  # 3DES para KCV legacy


# ---------------------------------------------------------------------------
# Helpers de I/O
# ---------------------------------------------------------------------------

def load_hex_value(value_or_path: str) -> bytes:
    """
    Acepta un componente de clave como:
      - cadena hexadecimal directa (cualquier longitud)
      - ruta a un archivo que contiene hex (con o sin espacios/saltos)

    La distinción se hace comprobando si el valor existe como archivo;
    de lo contrario se intenta parsear como hex directamente.
    """
    stripped = value_or_path.strip()
    path = Path(stripped)

    if path.is_file():
        raw = path.read_text(encoding="utf-8").strip()
    else:
        raw = stripped

    hex_clean = raw.replace(" ", "").replace("\n", "").replace("\r", "")

    if not all(c in "0123456789abcdefABCDEF" for c in hex_clean):
        raise ValueError(
            f"El valor '{value_or_path[:40]}…' no es hex válido ni una ruta de archivo existente."
        )

    return bytes.fromhex(hex_clean)


# ---------------------------------------------------------------------------
# Operaciones de clave
# ---------------------------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte. Exige longitudes iguales."""
    if len(a) != len(b):
        raise ValueError(
            f"Los componentes deben tener la misma longitud: {len(a)} vs {len(b)} bytes."
        )
    return bytes(x ^ y for x, y in zip(a, b))


def recombine_kek(component_1: str, component_2: str) -> bytes:
    """
    Recombina dos componentes de KEK mediante XOR.
    Cada argumento puede ser un valor hex directo o una ruta de archivo.
    """
    c1 = load_hex_value(component_1)
    c2 = load_hex_value(component_2)
    return xor_bytes(c1, c2)


# ---------------------------------------------------------------------------
# KCV
# ---------------------------------------------------------------------------

def cmac_kcv(key: bytes) -> str:
    """
    CMAC-KCV para claves AES (cualquier longitud válida: 16, 24 o 32 bytes).
    Calcula CMAC(key, 0x00 * 16) y retorna los primeros 3 bytes en hex mayúsculas.
    """
    c = CMAC(algorithms.AES(key))
    c.update(b"\x00" * 16)
    return c.finalize()[:3].hex().upper()


def tdes_kcv(key: bytes) -> str:
    """
    KCV clásico 3DES-ECB para claves legacy (usado en BDK 2-key 3DES).
    Cifra un bloque de ceros y retorna los primeros 3 bytes en hex mayúsculas.
    """
    cipher = Cipher(TripleDES(key), modes.ECB())
    enc = cipher.encryptor()
    out = enc.update(b"\x00" * 8) + enc.finalize()
    return out[:3].hex().upper()


def compute_kcv(key: bytes) -> str:
    """
    Selecciona automáticamente el método de KCV según el tamaño de la clave:
      - 16 bytes → 2-key 3DES → KCV TDES-ECB (convención legacy DUKPT)
      - 24/32 bytes → AES → KCV CMAC-AES
    """
    if len(key) == 16:
        return tdes_kcv(key)
    return cmac_kcv(key)


# ---------------------------------------------------------------------------
# Generación de claves
# ---------------------------------------------------------------------------

def generate_aes256_key() -> bytes:
    """Genera una clave AES-256 criptográficamente segura (32 bytes, CSPRNG)."""
    return os.urandom(32)
