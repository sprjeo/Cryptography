import struct
from typing import Optional
from .base_mode import EncryptionMode
from config import BLOCK_SIZE


class ECB(EncryptionMode):
   
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        print(f"ECB encrypt: входные данные {len(data)} байт")
        padded_data = self._pad_data(data)
        print(f"После набивки: {len(padded_data)} байт")
        
        result = b''
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            encrypted = self.cipher.encrypt_block(block)
            result += encrypted
        
        print(f"Зашифровано: {len(result)} байт")
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        print(f"ECB decrypt: входные данные {len(data)} байт")
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Длина зашифрованных данных должна быть кратна размеру блока")
        
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            decrypted = self.cipher.decrypt_block(block)
            result += decrypted
        
        print(f"После дешифрования: {len(result)} байт")
        unpadded = self._unpad_data(result)
        print(f"После удаления набивки: {len(unpadded)} байт")
        return unpadded


class CBC(EncryptionMode):
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        
        padded_data = self._pad_data(data)
        result = b''
        prev_block = iv
        
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            # XOR с предыдущим зашифрованным блоком (или IV)
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self.cipher.encrypt_block(xored)
            result += encrypted
            prev_block = encrypted
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Длина зашифрованных данных должна быть кратна размеру блока")
        
        result = b''
        prev_block = iv
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            decrypted = self.cipher.decrypt_block(block)
            # XOR с предыдущим зашифрованным блоком (или IV)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            result += xored
            prev_block = block
        
        return self._unpad_data(result)


class PCBC(EncryptionMode):
  
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        
        padded_data = self._pad_data(data)
        result = b''
        prev_plain = iv
        prev_cipher = iv
        
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            # XOR с предыдущим открытым и зашифрованным блоком
            xored = bytes(a ^ b ^ c for a, b, c in zip(block, prev_plain, prev_cipher))
            encrypted = self.cipher.encrypt_block(xored)
            result += encrypted
            prev_plain = block
            prev_cipher = encrypted
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Длина зашифрованных данных должна быть кратна размеру блока")
        
        result = b''
        prev_plain = iv
        prev_cipher = iv
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            decrypted = self.cipher.decrypt_block(block)
            # XOR с предыдущим открытым и зашифрованным блоком
            xored = bytes(a ^ b ^ c for a, b, c in zip(decrypted, prev_plain, prev_cipher))
            result += xored
            prev_plain = xored
            prev_cipher = block
        
        return self._unpad_data(result)


class CFB(EncryptionMode):
    
    def __init__(self, cipher, padding_mode, segment_size=BLOCK_SIZE):
        super().__init__(cipher, padding_mode)
        self.segment_size = segment_size
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        
        # В CFB режиме набивка не требуется
        result = b''
        register = iv
        
        for i in range(0, len(data), self.segment_size):
            encrypted = self.cipher.encrypt_block(register)
            segment = data[i:i+self.segment_size]
            
            # XOR с зашифрованным регистром
            xored = bytes(a ^ b for a, b in zip(segment, encrypted[:len(segment)]))
            result += xored
            
            # Сдвигаем регистр
            register = register[self.segment_size:] + xored
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        
        result = b''
        register = iv
        
        for i in range(0, len(data), self.segment_size):
            encrypted = self.cipher.encrypt_block(register)
            segment = data[i:i+self.segment_size]
            
            # Дешифрование в CFB - та же операция, что и шифрование
            xored = bytes(a ^ b for a, b in zip(segment, encrypted[:len(segment)]))
            result += xored
            
            # Сдвигаем регистр
            register = register[self.segment_size:] + segment
        
        return result


class OFB(EncryptionMode):
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV должен быть {BLOCK_SIZE} байт")
        
        # В OFB режиме набивка не требуется
        result = b''
        register = iv
        
        for i in range(0, len(data), BLOCK_SIZE):
            register = self.cipher.encrypt_block(register)
            block = data[i:i+BLOCK_SIZE]
            
            # XOR с зашифрованным регистром
            xored = bytes(a ^ b for a, b in zip(block, register[:len(block)]))
            result += xored
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        # OFB симметричен
        return self.encrypt(data, iv)


class CTR(EncryptionMode):
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if iv is None or len(iv) != BLOCK_SIZE // 2:
            raise ValueError(f"IV (nonce) должен быть {BLOCK_SIZE // 2} байт")
        
        # В CTR режиме набивка не требуется
        result = b''
        counter = 0
        
        for i in range(0, len(data), BLOCK_SIZE):
            # Формируем блок счетчика: IV + счетчик
            counter_bytes = struct.pack('>Q', counter)
            input_block = iv + counter_bytes
            encrypted = self.cipher.encrypt_block(input_block)
            
            block = data[i:i+BLOCK_SIZE]
            # XOR с зашифрованным блоком счетчика
            xored = bytes(a ^ b for a, b in zip(block, encrypted[:len(block)]))
            result += xored
            counter += 1
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        # CTR симметричен
        return self.encrypt(data, iv)


class RandomDelta(EncryptionMode):
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        # IV в этом режиме не используется напрямую
        import secrets
        
        padded_data = self._pad_data(data)
        result = b''
        
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            # Генерируем случайный IV для каждого блока
            block_iv = secrets.token_bytes(BLOCK_SIZE)
            # XOR с IV перед шифрованием
            xored = bytes(a ^ b for a, b in zip(block, block_iv))
            encrypted = self.cipher.encrypt_block(xored)
            # Сохраняем IV вместе с зашифрованным блоком
            result += block_iv + encrypted
        
        return result
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        if len(data) % (BLOCK_SIZE * 2) != 0:
            raise ValueError("Некорректная длина данных")
        
        result = b''
        
        for i in range(0, len(data), BLOCK_SIZE * 2):
            block_iv = data[i:i+BLOCK_SIZE]
            encrypted = data[i+BLOCK_SIZE:i+BLOCK_SIZE*2]
            
            decrypted = self.cipher.decrypt_block(encrypted)
            # XOR с сохраненным IV
            xored = bytes(a ^ b for a, b in zip(decrypted, block_iv))
            result += xored
        
        return self._unpad_data(result)
