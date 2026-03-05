"""
cli.py — Interfaz de línea de comandos para key_exchange.

Comandos disponibles:
  export-pek   Genera una PEK AES-256 y la exporta envuelta en un key block TR-31.
  import-bdk   Importa y valida la BDK desde un key block TR-31.
  decrypt-dukpt (bonus) Descifra un criptograma DUKPT 3DES-ECB.
"""

import argparse
import sys
from pathlib import Path

import psec

from .kek import (
    recombine_kek,
    cmac_kcv,
    compute_kcv,
    generate_aes256_key,
    load_hex_value,
)


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _resolve_and_validate_kek(args) -> bytes:
    """
    Recombina los dos componentes y valida el KCV.
    Termina con SystemExit si el KCV no coincide.
    """
    kek = recombine_kek(args.kek_component_1, args.kek_component_2)
    kcv_calc = cmac_kcv(kek)
    expected = args.kek_kcv.upper().strip()

    print(f"[KEK] KCV calculado : {kcv_calc}")
    print(f"[KEK] KCV esperado  : {expected}")

    if kcv_calc != expected:
        _abort(f"KCV de KEK no coincide. Verifique los componentes.\n"
               f"  Calculado : {kcv_calc}\n"
               f"  Esperado  : {expected}")

    print("[KEK] ✓ KCV válido — KEK recombinada correctamente.\n")
    return kek


def _abort(message: str) -> None:
    """Imprime el error y termina con código de salida 1."""
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(1)


def _load_keyblock(value_or_path: str) -> str:
    """Carga un TR-31 key block desde valor directo o archivo."""
    p = Path(value_or_path.strip())
    if p.is_file():
        return p.read_text(encoding="utf-8").strip()
    return value_or_path.strip()


# ---------------------------------------------------------------------------
# Comando: export-pek
# ---------------------------------------------------------------------------

def cmd_export_pek(args) -> None:
    """
    (1) Recombina y valida la KEK.
    (2) Genera una PEK AES-256 con os.urandom (CSPRNG).
    (3) La envuelve en un key block TR-31 versión D (AES Key Derivation).
    (4) Escribe el key block en el archivo de salida.
    (5) Imprime el KCV de la PEK para verificación por la contraparte.

    Nota de seguridad: el valor en claro de la PEK NO se imprime.
    """
    kek = _resolve_and_validate_kek(args)

    # Generar PEK
    pek = generate_aes256_key()
    pek_kcv = cmac_kcv(pek)

    # Construir header TR-31
    # version_id="D" → AES Key Derivation Binding Method (ANSI X9.143)
    # key_usage="P0" → PIN Encryption Key
    # algorithm="A"  → AES
    # mode_of_use="E" → Encrypt only (correcto para PEK según X9.143 tabla B-7)
    # exportability="N" → No re-exportable
    header = psec.tr31.Header(
        version_id="D",
        key_usage="P0",
        algorithm="A",
        mode_of_use="E",
        version_num="00",
        exportability="N",
    )

    key_block = psec.tr31.wrap(
        kbpk=kek,
        header=str(header),
        key=pek,
    )

    # Escribir archivo de salida
    out_path = Path(args.out)
    out_path.write_text(key_block + "\n", encoding="utf-8")

    print("[PEK] TR-31 Key Block generado:")
    print(f"  {key_block}")
    print(f"\n[PEK] KCV (CMAC-AES, primeros 3 bytes): {pek_kcv}")
    print(f"[PEK] Archivo de salida: {out_path.resolve()}")
    print("\n[PEK] ✓ PEK generada y exportada exitosamente.")


# ---------------------------------------------------------------------------
# Comando: import-bdk
# ---------------------------------------------------------------------------

def cmd_import_bdk(args) -> None:
    """
    (1) Recombina y valida la KEK.
    (2) Desenvoltura del key block TR-31 de la BDK.
    (3) Validación del KCV de la BDK (auto-detección TDES o CMAC según tamaño).
    """
    kek = _resolve_and_validate_kek(args)

    # Cargar key block (archivo o valor directo)
    bdk_kb = _load_keyblock(args.bdk_keyblock)

    # Unwrap TR-31
    try:
        _header, bdk = psec.tr31.unwrap(kbpk=kek, key_block=bdk_kb)
    except Exception as exc:
        _abort(f"No se pudo desenvolver el key block TR-31 de la BDK: {exc}")

    expected_kcv = args.bdk_kcv.upper().strip()

    # KCV auto-detectado según tamaño de clave
    kcv_calc = compute_kcv(bdk)
    method = "TDES-ECB" if len(bdk) == 16 else "CMAC-AES"

    print(f"[BDK] Tamaño de clave : {len(bdk) * 8} bits")
    print(f"[BDK] Método KCV      : {method}")
    print(f"[BDK] KCV calculado   : {kcv_calc}")
    print(f"[BDK] KCV esperado    : {expected_kcv}")

    if kcv_calc != expected_kcv:
        _abort(
            f"KCV de BDK no coincide ({method}).\n"
            f"  Calculado : {kcv_calc}\n"
            f"  Esperado  : {expected_kcv}"
        )

    print("\n[BDK] ✓ BDK desenvuelta y validada correctamente.")


# ---------------------------------------------------------------------------
# Comando: decrypt-dukpt (BONUS)
# ---------------------------------------------------------------------------

def cmd_decrypt_dukpt(args) -> None:
    """
    (BONUS) Deriva la future key DUKPT a partir de la BDK y el KSN,
    y descifra el criptograma 3DES-ECB.

    Usa la librería 'dukpt' si está disponible; si no, usa la implementación
    local dukpt_bonus (incluida en el repositorio).
    """
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.dirname(__file__)))
        import dukpt_bonus as _bonus
        _derive_future_key = _bonus.derive_future_key
        _decrypt = _bonus.tdes_decrypt_2key_ecb
    except ImportError:
        _abort("No se encontró dukpt_bonus.py. Asegúrese de que el archivo esté en la raíz del proyecto.")

    kek = _resolve_and_validate_kek(args)

    # Desenvolver BDK
    bdk_kb = _load_keyblock(args.bdk_keyblock)
    try:
        _header, bdk = psec.tr31.unwrap(kbpk=kek, key_block=bdk_kb)
    except Exception as exc:
        _abort(f"No se pudo desenvolver el key block TR-31 de la BDK: {exc}")

    ksn_bytes = bytes.fromhex(args.ksn.replace(" ", ""))
    ciphertext = bytes.fromhex(args.ciphertext.replace(" ", ""))

    # Derivar future key y descifrar
    future_key = _derive_future_key(bdk, ksn_bytes)
    plaintext = _decrypt(future_key, ciphertext)

    print(f"[DUKPT] KSN           : {args.ksn.upper()}")
    print(f"[DUKPT] Ciphertext    : {args.ciphertext.upper()}")
    print(f"[DUKPT] Plaintext     : {plaintext.hex().upper()}")
    try:
        print(f"[DUKPT] Plaintext     : {plaintext.decode('ascii')!r}")
    except UnicodeDecodeError:
        pass  # no es ASCII, mostrar solo hex


# ---------------------------------------------------------------------------
# Parser y entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="key_exchange",
        description="Herramienta de intercambio seguro de claves TR-31 (ANSI X9.143).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python -m key_exchange export-pek \\
      --kek-component-1 db375b... --kek-component-2 1e924a... \\
      --kek-kcv F74B90 --out pek.tr31

  python -m key_exchange import-bdk \\
      --kek-component-1 db375b... --kek-component-2 1e924a... \\
      --kek-kcv F74B90 \\
      --bdk-keyblock D0112B0TX00E0000... --bdk-kcv EABBDC

  python -m key_exchange decrypt-dukpt \\
      --kek-component-1 db375b... --kek-component-2 1e924a... \\
      --kek-kcv F74B90 \\
      --bdk-keyblock D0112B0TX00E0000... \\
      --ksn 729C77361E9A51E000F2 \\
      --ciphertext FCC832A91953151148E86A01BE9420AC
        """,
    )

    # Argumentos KEK comunes a todos los subcomandos
    kek_args = argparse.ArgumentParser(add_help=False)
    kek_args.add_argument("--kek-component-1", required=True,
                          metavar="HEX_OR_FILE",
                          help="Componente 1 de la KEK (hex directo o ruta de archivo).")
    kek_args.add_argument("--kek-component-2", required=True,
                          metavar="HEX_OR_FILE",
                          help="Componente 2 de la KEK (hex directo o ruta de archivo).")
    kek_args.add_argument("--kek-kcv", required=True,
                          metavar="HEX6",
                          help="KCV esperado de la KEK (6 caracteres hex, CMAC-AES).")

    sub = p.add_subparsers(dest="cmd", required=True, title="comandos")

    # export-pek
    exp = sub.add_parser("export-pek", parents=[kek_args],
                         help="Genera una PEK AES-256 y la exporta en key block TR-31.")
    exp.add_argument("--out", required=True, metavar="FILE",
                     help="Ruta del archivo de salida para el key block TR-31 de la PEK.")

    # import-bdk
    imp = sub.add_parser("import-bdk", parents=[kek_args],
                         help="Importa y valida la BDK desde un key block TR-31.")
    imp.add_argument("--bdk-keyblock", required=True, metavar="KB_OR_FILE",
                     help="Key block TR-31 de la BDK (valor directo o ruta de archivo).")
    imp.add_argument("--bdk-kcv", required=True, metavar="HEX6",
                     help="KCV esperado de la BDK (6 caracteres hex).")

    # decrypt-dukpt (bonus)
    dukpt_cmd = sub.add_parser("decrypt-dukpt", parents=[kek_args],
                                help="[BONUS] Descifra un criptograma DUKPT 3DES-ECB.")
    dukpt_cmd.add_argument("--bdk-keyblock", required=True, metavar="KB_OR_FILE",
                            help="Key block TR-31 de la BDK.")
    dukpt_cmd.add_argument("--ksn", required=True, metavar="HEX",
                            help="Key Serial Number (KSN) en hex.")
    dukpt_cmd.add_argument("--ciphertext", required=True, metavar="HEX",
                            help="Criptograma 3DES-ECB en hex.")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "export-pek": cmd_export_pek,
        "import-bdk": cmd_import_bdk,
        "decrypt-dukpt": cmd_decrypt_dukpt,
    }

    try:
        dispatch[args.cmd](args)
        return 0
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[INFO] Operación cancelada por el usuario.", file=sys.stderr)
        return 130
    except Exception as exc:
        _abort(f"Error inesperado: {exc}")
        return 1
