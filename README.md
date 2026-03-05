# key_exchange — MercadoPago Security Challenge

Herramienta de línea de comandos para el intercambio seguro de claves criptográficas siguiendo el estándar **TR-31 / ANSI X9.143**.

## Descripción

Implementa tres operaciones criptográficas:

1. **Recombinación y validación de la KEK** a partir de dos componentes XOR distribuidos por canales independientes, con verificación por CMAC-KCV.
2. **Generación y exportación de la PEK** (PIN Encryption Key) envuelta en un key block TR-31.
3. **Importación y validación de la BDK** (Base Derivation Key) desenvuelta desde un key block TR-31.
4. *(Bonus)* **Descifrado DUKPT** derivando la future key a partir de la BDK y el KSN.

## Instalación

```bash
# 1. Crear entorno virtual
python -m venv .venv
# Si falla, intentar con: python3 -m venv .venv

# 2. Activar el entorno virtual
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate.bat         # Windows (CMD)
.venv\Scripts\Activate.ps1         # Windows (PowerShell)

# ⚠️ Windows PowerShell: si aparece error "PSSecurityException" o
# "la ejecución de scripts está deshabilitada", ejecutar primero:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Confirmar con S. Solo se necesita hacer una vez por equipo.
# Alternativamente, usar CMD y correr activate.bat en lugar de Activate.ps1.

# 3. Instalar dependencias
pip install -r requirements.txt
```

### Requisitos previos

- **Python 3.8 o superior** (`python --version` para verificar)
- pip actualizado: `pip install --upgrade pip`

### Solución de problemas comunes

**Error: `ModuleNotFoundError: No module named 'Crypto'` o falla en `dukpt_bonus.py`**
```bash
# Conflicto entre pycrypto (viejo) y pycryptodome. Solución:
pip uninstall pycrypto
pip install pycryptodome
```

**Error: `cannot import name 'TripleDES' from 'cryptography.hazmat.decrepit...'`**
```bash
# La librería cryptography instalada es anterior a la versión 42. Solución:
pip install --upgrade "cryptography>=42.0"
```

**Error: `ModuleNotFoundError: No module named 'psec'` u otras dependencias**
```bash
# Verificar que el entorno virtual está activado (debe aparecer (.venv) en el prompt)
# Luego reinstalar:
pip install -r requirements.txt
```

## Uso

### Exportar PEK

```bash
python -m key_exchange export-pek --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 --kek-kcv F74B90 --out pek.tr31
```

**Salida esperada:**
```
[KEK] KCV calculado : F74B90
[KEK] KCV esperado  : F74B90
[KEK] ✓ KCV válido — KEK recombinada correctamente.

[PEK] TR-31 Key Block generado:
  D0144P0AE00N0000...
[PEK] KCV (CMAC-AES, primeros 3 bytes): XXXXXX
[PEK] Archivo de salida: /ruta/pek.tr31
[PEK] ✓ PEK generada y exportada exitosamente.
```

### Importar BDK

```bash
python -m key_exchange import-bdk --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 --kek-kcv F74B90 --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 --bdk-kcv EABBDC
```

### (Bonus) Descifrar DUKPT

```bash
python -m key_exchange decrypt-dukpt --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 --kek-kcv F74B90 --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 --ksn 729C77361E9A51E000F2 --ciphertext FCC832A91953151148E86A01BE9420AC
```

> Los argumentos `--kek-component-1` y `--kek-component-2` aceptan tanto el valor hex directamente como la ruta a un archivo de texto que lo contenga.

## Decisiones de diseño

### Seguridad

- **Las claves en claro no se imprimen en stdout.** Solo se exponen los KCVs (3 bytes), que son suficientes para verificación sin comprometer el material criptográfico.
- La KEK se mantiene en memoria únicamente durante la ejecución del proceso; no se persiste en disco.
- La PEK se genera con `os.urandom` (CSPRNG del sistema operativo).
- El header TR-31 de la PEK usa `mode_of_use="E"` (Encrypt only), conforme a la tabla B-7 de ANSI X9.143.

### KCV adaptativo

`compute_kcv()` selecciona automáticamente el método según el tamaño de la clave:
- **16 bytes** → KCV TDES-ECB (convención legacy, típico en BDK 2-key DUKPT)
- **24 / 32 bytes** → KCV CMAC-AES

### Detección de input flexible

`load_hex_value()` usa `Path.is_file()` para decidir si el argumento es una ruta o un valor hex directo, eliminando la heurística frágil basada en longitud.

## Estructura

```
key_exchange/
├── __init__.py        Metadatos del paquete
├── __main__.py        Entry point: python -m key_exchange
├── kek.py             Primitivas criptográficas (XOR, KCV, generación)
└── cli.py             CLI (argparse), subcomandos y lógica de flujo
dukpt_bonus.py         Implementación DUKPT standalone con pycryptodome
requirements.txt
README.md
answers.md             Respuestas a las preguntas teóricas
```

## Dependencias

| Librería | Uso |
|---|---|
| `psec` | Wrap/unwrap TR-31, construcción de headers |
| `cryptography` | AES-CMAC, 3DES-ECB |
| `pycryptodome` | Derivación DUKPT en `dukpt_bonus.py` (se instala como dependencia de `dukpt`) |

## Notas de compatibilidad

La librería `dukpt` 1.0.1 disponible en PyPI no expone la API esperada (`derive_future_key`, `decrypt_3des_ecb`). Por eso el comando `decrypt-dukpt` usa directamente `dukpt_bonus.py`, una implementación standalone del algoritmo NRKGP (Non-Reversible Key Generation Process) que usa `pycryptodome` — el cual se instala automáticamente junto con `dukpt` al correr `pip install -r requirements.txt`.

No se requiere ningún paso adicional: `dukpt_bonus.py` está incluido en el repositorio y es detectado automáticamente por `cli.py`.

## Respuestas teóricas

Ver [`answers.md`](answers.md).