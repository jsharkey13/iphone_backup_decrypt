#####
# This code is derived from 'iphone-dataprotection':
# https://code.google.com/p/iphone-dataprotection/
#     iphone-dataprotection/python_scripts/keystore/keybag.py
#     iphone-dataprotection/python_scripts/crypto/aes.py
# Original License: https://opensource.org/licenses/BSD-3-Clause
#
# It is now unused and remains for reference purposes only.
#####

import struct
import warnings

import Crypto.Cipher.AES

from . import utils

__all__ = ["Keybag", "AESdecryptCBC", "removePadding"]


# Retain these names at the top-level for backwards-compatibility only:
pbkdf2_hmac = utils.pbkdf2_hmac
_MAX_DPIC_ITERATIONS = utils._MAX_DPIC_ITERATIONS
_MAX_ITER_ITERATIONS = utils._MAX_ITER_ITERATIONS
_validated_iteration_count = utils.BackupKeyBag._validate_iterations


class Keybag:
    def __init__(self, data):
        warnings.warn("Keybag is deprecated. Consider using 'utils.BackupKeyBag' instead.", DeprecationWarning, stacklevel=2)
        self.type = None
        self.uuid = None
        self.wrap = None
        self.deviceKey = None
        self.attrs = {}
        self.classKeys = {}
        self.KeyBagKeys = None  # DATASIGN blob
        self.parseBinaryBlob(data)

    def parseBinaryBlob(self, data):
        currentClassKey = None

        for tag, data in _loopTLVBlocks(data):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == b"TYPE":
                self.type = data
                if self.type > 3:
                    print("FAIL: keybag type > 3 : %d" % self.type)
            elif tag == b"UUID" and self.uuid is None:
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == b"UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
                currentClassKey = {b"UUID": data}
            elif tag in [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey

    def unlockWithPassphrase(self, passphrase):
        # Validate iteration counts before attempting to use them:
        dpic_iterations = _validated_iteration_count(self.attrs[b"DPIC"], "DPIC", _MAX_DPIC_ITERATIONS)
        iter_iterations = _validated_iteration_count(self.attrs[b"ITER"], "ITER", _MAX_ITER_ITERATIONS)
        # Decrypt keys:
        passphrase_round1 = pbkdf2_hmac('sha256', passphrase, self.attrs[b"DPSL"], dpic_iterations, 32)
        passphrase_key = pbkdf2_hmac('sha1', passphrase_round1, self.attrs[b"SALT"], iter_iterations, 32)
        for classkey in self.classKeys.values():
            if b"WPKY" not in classkey:
                continue
            WRAP_PASSPHRASE = 2
            if classkey[b"WRAP"] & WRAP_PASSPHRASE:
                k = _AESUnwrap(passphrase_key, classkey[b"WPKY"])
                if not k:
                    return False
                classkey[b"KEY"] = k
        return True

    def unwrapKeyForClass(self, protection_class, persistent_key):
        ck = self.classKeys[protection_class][b"KEY"]
        if len(persistent_key) != 0x28:
            raise Exception("Invalid key length")
        return _AESUnwrap(ck, persistent_key)


def _loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i+4]
        length = struct.unpack(">L", blob[i+4:i+8])[0]
        data = blob[i+8:i+8+length]
        yield (tag, data)
        i += 8 + length


def _unpack64bit(s):
    return struct.unpack(">Q", s)[0]


def _pack64bit(s):
    return struct.pack(">Q", s)


def _AESUnwrap(kek, wrapped):
    warnings.warn("_AESUnwrap is deprecated. Consider using 'utils.aes_unwrap' instead.", DeprecationWarning, stacklevel=2)
    C = []
    for i in range(len(wrapped)//8):
        C.append(_unpack64bit(wrapped[i * 8:i * 8 + 8]))
    n = len(C) - 1
    R = [0] * (n+1)
    A = C[0]

    for i in range(1, n+1):
        R[i] = C[i]

    for j in reversed(range(0, 6)):
        for i in reversed(range(1, n+1)):
            todec = _pack64bit(A ^ (n * j + i))
            todec += _pack64bit(R[i])
            B = Crypto.Cipher.AES.new(kek, Crypto.Cipher.AES.MODE_ECB).decrypt(todec)
            A = _unpack64bit(B[:8])
            R[i] = _unpack64bit(B[8:])

    if A != 0xa6a6a6a6a6a6a6a6:
        return None
    res = b"".join(map(_pack64bit, R[1:]))
    return res


def AESdecryptCBC(data, key, iv=b"\x00" * 16):
    warnings.warn("AESdecryptCBC is deprecated. Consider using 'utils.aes_decrypt_cbc' instead.", DeprecationWarning, stacklevel=2)
    if len(data) % 16:
        print("WARN: AESdecryptCBC: data length not /16, truncating")
        data = data[0:(len(data)/16) * 16]
    data = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(data)
    return data


def removePadding(data, blocksize=16):
    warnings.warn("removePadding is deprecated. Consider using 'utils.remove_cbc_padding' instead.", DeprecationWarning, stacklevel=2)
    n = int(data[-1])  # RFC 1423: last byte contains number of padding bytes.
    if n > blocksize or n > len(data):
        raise Exception('Invalid CBC padding')
    return data[:-n]
