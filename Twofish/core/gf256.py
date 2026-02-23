from typing import Optional
from config import GF256_POLYNOMIALS


class GF256:
    
    def __init__(self, polynomial: int = 0x11B):
  
        if polynomial not in GF256_POLYNOMIALS:
            raise ValueError(f"Неподдерживаемый полином: {hex(polynomial)}")
        
        self.polynomial = polynomial
        self._init_tables()
    
    def _init_tables(self):

        self.exp_table = [0] * 512
        self.log_table = [0] * 256
        
        x = 1
        for i in range(1, 256):
            x <<= 1
            if x & 0x100:
                x ^= self.polynomial
            self.exp_table[i] = x
            self.log_table[x] = i
        
        # Заполняем exp_table для индексов > 255
        for i in range(255, 512):
            self.exp_table[i] = self.exp_table[i - 255]
    
    def add(self, a: int, b: int) -> int:
        #Сложение (XOR)
        return a ^ b
    
    def sub(self, a: int, b: int) -> int:
        #Вычитание (XOR)
        return a ^ b
    
    def mul(self, a: int, b: int) -> int:
        #Умножение 
        if a == 0 or b == 0:
            return 0
        return self.exp_table[self.log_table[a] + self.log_table[b]]
    
    def div(self, a: int, b: int) -> int:
        #Деление 
        if b == 0:
            raise ZeroDivisionError("Деление на ноль в GF(2^8)")
        if a == 0:
            return 0
        return self.exp_table[(self.log_table[a] - self.log_table[b]) % 255]
    
    def pow(self, a: int, power: int) -> int:
        #Возведение в степень 
        if a == 0:
            return 0 if power > 0 else float('inf')
        if power == 0:
            return 1
        return self.exp_table[(self.log_table[a] * power) % 255]
    
    def inverse(self, a: int) -> int:
        #Обратный элемент 
        if a == 0:
            raise ZeroDivisionError("Нулевой элемент не имеет обратного")
        return self.exp_table[255 - self.log_table[a]]