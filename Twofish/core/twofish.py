"""Базовая реализация алгоритма Twofish"""

import struct
from typing import List
from .gf256 import GF256
from config import BLOCK_SIZE, ROUNDS


class Twofish:
    """Реализация блочного шифра Twofish"""
    
    # S-блоки Twofish в правильном формате
    Q0 = [
        [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
        [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD]
    ]
    
    Q1 = [
        [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
        [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8]
    ]
    
    # Матрица MDS
    MDS = [
        [0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]
    ]
    
    def __init__(self, key: bytes, polynomial: int = 0x11B):

        if len(key) not in [16, 24, 32]:
            raise ValueError(f"Ключ должен быть 16, 24 или 32 байта, получено {len(key)}")
        
        self.key = key
        self.key_len = len(key)
        self.gf = GF256(polynomial)
        self.N = self.key_len // 8  # Количество 64-битных слов в ключе
        
        # Преобразование ключа в 32-битные слова
        self._me = [0] * self.N
        self._mo = [0] * self.N
        
        for i in range(self.N):
            # Берем 8 байт для каждого 64-битного слова
            offset = i * 8
            self._me[i] = struct.unpack('<I', key[offset:offset+4])[0]
            self._mo[i] = struct.unpack('<I', key[offset+4:offset+8])[0]
        
        # Генерация S-боксов
        self._s = [0] * (self.N * 2)
        self._generate_sboxes()
        
        # Генерация раундовых ключей
        self._round_keys = [0] * 40
        self._generate_round_keys()
    
    def _q0(self, x: int) -> int:
        #Q0 перестановка для 4-битного входа
        a0 = x >> 4
        b0 = x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 0xF
        a2 = self.Q0[0][a1]
        b2 = self.Q0[1][b1]
        return (a2 << 4) | b2
    
    def _q1(self, x: int) -> int:
        #Q1 перестановка для 4-битного входа
        a0 = x >> 4
        b0 = x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 0xF
        a2 = self.Q1[0][a1]
        b2 = self.Q1[1][b1]
        return (a2 << 4) | b2
    
    def _h(self, x: int, key: List[int]) -> int:

        # Разбиваем на байты
        b = [(x >> (8 * i)) & 0xFF for i in range(4)]
        
        # Применяем Q-перестановки
        for i in range(4):
            if i == 0 or i == 2:
                b[i] = self._q0(b[i])
            else:
                b[i] = self._q1(b[i])
        
        # XOR с ключом
        for k in key:
            for j in range(4):
                b[j] ^= (k >> (8 * j)) & 0xFF
            
            # Снова Q-перестановки
            for j in range(4):
                if j == 0 or j == 2:
                    b[j] = self._q0(b[j])
                else:
                    b[j] = self._q1(b[j])
        
        # MDS матричное умножение
        result = 0
        for i in range(4):
            y = 0
            for j in range(4):
                y ^= self.gf.mul(self.MDS[i][j], b[j])
            result |= (y << (8 * i))
        
        return result & 0xFFFFFFFF
    
    def _generate_sboxes(self):
        #Генерация S-боксов из ключа
        for i in range(self.N):
            x = self._me[i]
            for j in range(4):
                self._s[2*i + (j>>2)] = (self._s[2*i + (j>>2)] << 8) | (x & 0xFF)
                x >>= 8
            
            x = self._mo[i]
            for j in range(4):
                self._s[2*i + (j>>2) + 1] = (self._s[2*i + (j>>2) + 1] << 8) | (x & 0xFF)
                x >>= 8
    
    def _generate_round_keys(self):
        #Генерация раундовых ключей
        rho = 0x01010101
        for i in range(20):
            # Вычисляем A и B
            a = self._h(i * 2 * rho, self._me)
            b = self._h((i * 2 + 1) * rho, self._mo)
            b = ((b << 8) & 0xFFFFFFFF) | (b >> 24)  # Циклический сдвиг влево на 8
            
            # Формируем раундовые ключи
            self._round_keys[2*i] = (a + b) & 0xFFFFFFFF
            self._round_keys[2*i + 1] = ((a + 2*b) & 0xFFFFFFFF) << 9 | ((a + 2*b) >> 23)
            self._round_keys[2*i + 1] &= 0xFFFFFFFF
    
    def encrypt_block(self, block: bytes) -> bytes:
      
        #Шифрование одного 16-байтового блока
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Размер блока должен быть {BLOCK_SIZE} байт")
        
        # Разбиваем блок на 4 32-битных слова
        x = list(struct.unpack('<4I', block))
        
        # Входное отбеливание
        for i in range(4):
            x[i] ^= self._round_keys[i]
        
        # 16 раундов
        for r in range(ROUNDS):
            # Вычисляем g-функции
            t0 = self._h(x[0], self._s)
            t1 = self._h(x[1], self._s)
            
            # PHT и добавление раундовых ключей
            x[2] ^= (t0 + t1 + self._round_keys[2*r + 8]) & 0xFFFFFFFF
            x[2] = (x[2] >> 1) | ((x[2] & 1) << 31)
            
            x[3] = ((x[3] << 1) | (x[3] >> 31)) & 0xFFFFFFFF
            x[3] ^= (t0 + 2*t1 + self._round_keys[2*r + 9]) & 0xFFFFFFFF
            
            # Перестановка слов
            x[0], x[1], x[2], x[3] = x[2], x[3], x[0], x[1]
        
        # Обратная перестановка
        x[0], x[1], x[2], x[3] = x[2], x[3], x[0], x[1]
        
        # Выходное отбеливание
        for i in range(4):
            x[i] ^= self._round_keys[i + 4]
        
        return struct.pack('<4I', *x)
    
    def decrypt_block(self, block: bytes) -> bytes:
        """Дешифрование одного 16-байтового блока"""
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Размер блока должен быть {BLOCK_SIZE} байт")
        
        # Разбиваем блок на 4 32-битных слова
        x = list(struct.unpack('<4I', block))
        
        # Входное отбеливание (для дешифрования)
        for i in range(4):
            x[i] ^= self._round_keys[i + 4]
        
        # Обратные 16 раундов
        x[0], x[1], x[2], x[3] = x[2], x[3], x[0], x[1]
        
        for r in range(ROUNDS - 1, -1, -1):
            x[0], x[1], x[2], x[3] = x[2], x[3], x[0], x[1]
            
            t0 = self._h(x[0], self._s)
            t1 = self._h(x[1], self._s)
            
            x[3] ^= (t0 + 2*t1 + self._round_keys[2*r + 9]) & 0xFFFFFFFF
            x[3] = ((x[3] << 1) | (x[3] >> 31)) & 0xFFFFFFFF
            
            x[2] = (x[2] >> 1) | ((x[2] & 1) << 31)
            x[2] ^= (t0 + t1 + self._round_keys[2*r + 8]) & 0xFFFFFFFF
        
        # Выходное отбеливание (для дешифрования)
        x[0], x[1], x[2], x[3] = x[2], x[3], x[0], x[1]
        for i in range(4):
            x[i] ^= self._round_keys[i]
        
        return struct.pack('<4I', *x)