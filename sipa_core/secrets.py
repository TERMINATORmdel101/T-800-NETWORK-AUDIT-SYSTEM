"""Chiffrement des secrets via la DPAPI de Windows.

Le mot de passe SMTP et les URL de webhook etaient stockes en clair dans
config.json. Ce module les chiffre avec la Data Protection API de Windows
(CryptProtectData) : la valeur n'est dechiffrable que par le meme compte
utilisateur Windows, sans qu'aucune cle n'ait a etre gardee par l'application
et sans nouvelle dependance.

Hors Windows (ou si la DPAPI echoue), les valeurs restent en clair : on ne
peut pas garantir mieux sans dependance, mais rien ne casse.
"""

import base64
import ctypes
import platform
from ctypes import wintypes

#: Prefixe marquant une valeur chiffree, pour distinguer d'un ancien secret
#: encore en clair et rester retrocompatible.
PREFIX = "dpapi:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def is_available() -> bool:
    """Vrai si la DPAPI est utilisable (Windows avec crypt32)."""
    if platform.system() != "Windows":
        return False
    try:
        ctypes.windll.crypt32  # noqa: B018 - simple test de disponibilite
        return True
    except Exception:
        return False


def protect(plaintext: str) -> str:
    """Chiffre une chaine. Renvoie 'dpapi:<base64>' ou le texte tel quel.

    Idempotent : une valeur deja chiffree est renvoyee inchangee.
    """
    if not plaintext or plaintext.startswith(PREFIX):
        return plaintext
    if not is_available():
        return plaintext

    try:
        source = _blob(plaintext.encode("utf-8"))
        result = _DataBlob()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source), None, None, None, None, 0,
            ctypes.byref(result))
        if not ok:
            return plaintext
        encrypted = _blob_bytes(result)
        ctypes.windll.kernel32.LocalFree(result.pbData)
        return PREFIX + base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return plaintext


def unprotect(value: str) -> str:
    """Dechiffre une valeur 'dpapi:...'. Une valeur en clair est renvoyee telle."""
    if not value or not value.startswith(PREFIX):
        return value
    if not is_available():
        return value

    try:
        raw = base64.b64decode(value[len(PREFIX):])
        source = _blob(raw)
        result = _DataBlob()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source), None, None, None, None, 0,
            ctypes.byref(result))
        if not ok:
            return value
        decrypted = _blob_bytes(result)
        ctypes.windll.kernel32.LocalFree(result.pbData)
        return decrypted.decode("utf-8")
    except Exception:
        return value


def is_protected(value: str) -> bool:
    """Vrai si la valeur est deja chiffree."""
    return bool(value) and value.startswith(PREFIX)
