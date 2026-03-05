"""Permite ejecutar el paquete directamente: python -m key_exchange <comando>"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
