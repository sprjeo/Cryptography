import os
from typing import BinaryIO, Tuple, Optional


class FileHandler:
  
    CHUNK_SIZE = 64 * 1024  # 64 KB chunks for processing
    
    @staticmethod
    def read_file(filepath: str) -> bytes:
       
        with open(filepath, 'rb') as f:
            return f.read()
    
    @staticmethod
    def write_file(filepath: str, data: bytes):
        
        with open(filepath, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def read_chunks(filepath: str, chunk_size: int = CHUNK_SIZE):
        
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    
    @staticmethod
    def write_chunks(filepath: str, chunks):
        
        with open(filepath, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)
    
    @staticmethod
    def get_file_info(filepath: str) -> Tuple[str, int]:
        
        filename = os.path.basename(filepath)
        size = os.path.getsize(filepath)
        return filename, size
    
    @staticmethod
    def ensure_directory(filepath: str):
        
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
