import sys
import traceback
import argparse
from typing import Dict, Any, Optional

from core.twofish import Twofish
from core.gf256 import GF256
from modes.encryption_modes import (
    ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
)
from padding.padding_schemes import PaddingMode
from utils.file_handler import FileHandler
from utils.parallel_processor import ParallelProcessor
from config import BLOCK_SIZE


class TwofishCipher:
    
    MODES = {
        'ecb': ECB,
        'cbc': CBC,
        'pcbc': PCBC,
        'cfb': CFB,
        'ofb': OFB,
        'ctr': CTR,
        'randomdelta': RandomDelta
    }
    
    def __init__(self, config: Dict[str, Any]):
      
        self.config = config
        self.key = bytes.fromhex(config['key'])
        self.polynomial = config.get('polynomial', 0x11B)
        
        print(f"Инициализация Twofish с ключом длиной {len(self.key)} байт")
        print(f"Используемый полином: {hex(self.polynomial)}")
        
        # Создаем экземпляр шифра
        self.cipher = Twofish(self.key, self.polynomial)
        
        # Определяем режим шифрования
        mode_name = config['mode'].lower()
        if mode_name not in self.MODES:
            raise ValueError(f"Неподдерживаемый режим: {mode_name}")
        
        mode_class = self.MODES[mode_name]
        padding_mode = PaddingMode(config['padding'].lower())
        
        print(f"Режим шифрования: {mode_name}")
        print(f"Режим набивки: {padding_mode.value}")
        
        # Создаем экземпляр режима
        self.mode = mode_class(self.cipher, padding_mode)
        
        # Создаем процессор для параллельной обработки
        self.processor = ParallelProcessor(max_workers=config.get('threads', 4))
        print(f"Количество потоков: {config.get('threads', 4)}")
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """Шифрование данных"""
        return self.mode.encrypt(data, iv)
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """Дешифрование данных"""
        return self.mode.decrypt(data, iv)
    
    def encrypt_file(self, input_file: str, output_file: str, iv: Optional[bytes] = None):
        """Шифрование файла"""
        print(f"Чтение файла: {input_file}")
        data = FileHandler.read_file(input_file)
        print(f"Размер данных: {len(data)} байт")
        
        print("Шифрование...")
        encrypted = self.encrypt(data, iv)
        print(f"Размер зашифрованных данных: {len(encrypted)} байт")
        
        print(f"Запись в файл: {output_file}")
        FileHandler.write_file(output_file, encrypted)
        print(f"Файл зашифрован: {output_file}")
    
    def decrypt_file(self, input_file: str, output_file: str, iv: Optional[bytes] = None):
        """Дешифрование файла"""
        print(f"Чтение файла: {input_file}")
        data = FileHandler.read_file(input_file)
        print(f"Размер данных: {len(data)} байт")
        
        print("Дешифрование...")
        decrypted = self.decrypt(data, iv)
        print(f"Размер расшифрованных данных: {len(decrypted)} байт")
        
        print(f"Запись в файл: {output_file}")
        FileHandler.write_file(output_file, decrypted)
        print(f"Файл расшифрован: {output_file}")


def read_config_from_file(filename: str) -> Dict[str, Any]:
    #Чтение конфигурации из текстового файла
    config = {}
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'key':
                        config['key'] = value
                    elif key == 'mode':
                        config['mode'] = value.lower()
                    elif key == 'padding':
                        config['padding'] = value.lower()
                    elif key == 'polynomial':
                        config['polynomial'] = int(value, 16)
                    elif key == 'iv':
                        config['iv'] = value
                    elif key == 'threads':
                        config['threads'] = int(value)
                    elif key == 'operation':
                        config['operation'] = value.lower()
                    elif key == 'input':
                        config['input'] = value
                    elif key == 'output':
                        config['output'] = value
    except FileNotFoundError:
        print(f"Ошибка: файл конфигурации '{filename}' не найден")
        raise
    
    # Проверка обязательных параметров
    required = ['key', 'mode', 'padding', 'operation', 'input']
    missing = [req for req in required if req not in config]
    if missing:
        raise ValueError(f"Отсутствуют обязательные параметры: {', '.join(missing)}")
    
    # Значения по умолчанию
    if 'output' not in config:
        if config['operation'] == 'encrypt':
            config['output'] = config['input'] + '.enc'
        else:
            config['output'] = config['input'] + '.dec'
    
    if 'threads' not in config:
        config['threads'] = 4
    
    return config


def print_config(config: Dict[str, Any]):
    print("\nКонфигурация загружена из файла:")
    for key, value in config.items():
        if key == 'key':
            print(f"  {key}: {value[:32]}... (длина: {len(value)//2} байт)")
        else:
            print(f"  {key}: {value}")
    print()


def main():
    parser = argparse.ArgumentParser(description='Twofish шифрование файлов')
    parser.add_argument('config_file', nargs='?', default='input.txt',
                       help='Файл конфигурации (по умолчанию input.txt)')
    
    args = parser.parse_args()
    
    try:
        # Читаем конфигурацию из файла
        config = read_config_from_file(args.config_file)
        print_config(config)
        
        # Создание шифра
        cipher = TwofishCipher(config)
        
        # Подготовка IV
        iv = None
        if 'iv' in config and config['iv']:
            try:
                iv = bytes.fromhex(config['iv'])
                required_modes = ['cbc', 'pcbc', 'cfb', 'ofb']
                if config['mode'].lower() in required_modes and len(iv) != BLOCK_SIZE:
                    print(f"Предупреждение: IV должен быть {BLOCK_SIZE} байт для режима {config['mode']}")
            except ValueError:
                print(f"Ошибка: некорректный формат IV (должен быть hex)")
                raise
        
        # Выполнение операции
        if config['operation'] == 'encrypt':
            cipher.encrypt_file(config['input'], config['output'], iv)
        elif config['operation'] == 'decrypt':
            cipher.decrypt_file(config['input'], config['output'], iv)
        else:
            print(f"Ошибка: неизвестная операция '{config['operation']}'")
            return 1
        
        print("\nОперация успешно завершена!")
        return 0
        
    except FileNotFoundError as e:
        print(f"\nОшибка: файл не найден - {e}")
        return 1
    except ValueError as e:
        print(f"\nОшибка в параметрах: {e}")
        return 1
    except Exception as e:
        print(f"\nНепредвиденная ошибка: {e}")
        print("\nДетали ошибки:")
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())