from enum import Enum
from typing import Callable
import secrets


class PaddingMode(Enum):
    ZEROS = "zeros"
    ANSI_X923 = "ansi_x923"
    PKCS7 = "pkcs7"
    ISO_10126 = "iso_10126"


class Padding:
    
    @staticmethod
    def pad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
        
        pad_len = block_size - (len(data) % block_size)
        
        if mode == PaddingMode.ZEROS:
            return data + bytes(pad_len)
        
        elif mode == PaddingMode.ANSI_X923:
            # ANSI X9.23: последний байт - длина, остальные - нули
            return data + bytes(pad_len - 1) + bytes([pad_len])
        
        elif mode == PaddingMode.PKCS7:
            # PKCS7: все байты набивки равны длине набивки
            return data + bytes([pad_len] * pad_len)
        
        elif mode == PaddingMode.ISO_10126:
            # ISO 10126: последний байт - длина, остальные - случайные
            if pad_len == block_size:
                return data + secrets.token_bytes(pad_len - 1) + bytes([pad_len])
            return data + secrets.token_bytes(pad_len - 1) + bytes([pad_len])
        
        else:
            raise ValueError(f"Неподдерживаемый режим набивки: {mode}")
    
    @staticmethod
    def unpad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
        
        if len(data) % block_size != 0:
            raise ValueError("Длина данных должна быть кратна размеру блока")
        
        if mode == PaddingMode.ZEROS:
            # Удаляем нули в конце
            return data.rstrip(b'\x00')
        
        elif mode == PaddingMode.ANSI_X923:
            pad_len = data[-1]
            if pad_len > block_size:
                raise ValueError("Некорректная набивка ANSI X9.23")
            if not all(b == 0 for b in data[-pad_len:-1]):
                raise ValueError("Некорректная набивка ANSI X9.23")
            return data[:-pad_len]
        
        elif mode == PaddingMode.PKCS7:
            pad_len = data[-1]
            if pad_len > block_size:
                raise ValueError("Некорректная набивка PKCS7")
            if not all(b == pad_len for b in data[-pad_len:]):
                raise ValueError("Некорректная набивка PKCS7")
            return data[:-pad_len]
        
        elif mode == PaddingMode.ISO_10126:
            pad_len = data[-1]
            if pad_len > block_size:
                raise ValueError("Некорректная набивка ISO 10126")
            return data[:-pad_len]
        
        else:
            raise ValueError(f"Неподдерживаемый режим набивки: {mode}")
