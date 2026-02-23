from abc import ABC, abstractmethod
from typing import Optional
from core.twofish import Twofish
from padding.padding_schemes import Padding, PaddingMode
from config import BLOCK_SIZE


class EncryptionMode(ABC):

    def __init__(self, cipher: Twofish, padding_mode: PaddingMode):
   
        self.cipher = cipher
        self.padding_mode = padding_mode
    
    @abstractmethod
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        pass
    
    @abstractmethod
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        pass
    
    def _pad_data(self, data: bytes) -> bytes:
        #Добавление набивки к данным
        return Padding.pad(data, BLOCK_SIZE, self.padding_mode)
    
    def _unpad_data(self, data: bytes) -> bytes:
        #Удаление набивки из данных
        return Padding.unpad(data, BLOCK_SIZE, self.padding_mode)
