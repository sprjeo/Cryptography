import asyncio
import concurrent.futures
from typing import Callable, List, Any, Optional
from functools import partial


class ParallelProcessor:
   
    def __init__(self, max_workers: Optional[int] = None):
        
        self.max_workers = max_workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    
    def process_blocks_parallel(self, 
                               data: bytes, 
                               block_size: int,
                               process_func: Callable[[bytes], bytes],
                               use_threads: bool = True) -> bytes:
        
        if not use_threads:
            # Последовательная обработка
            result = b''
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                result += process_func(block)
            return result
        
        # Подготовка блоков для параллельной обработки
        blocks = []
        positions = []
        for i in range(0, len(data), block_size):
            blocks.append(data[i:i+block_size])
            positions.append(i)
        
        # Параллельная обработка
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            processed_blocks = list(executor.map(process_func, blocks))
        
        # Сборка результата с сохранением порядка
        result = bytearray(len(data))
        for pos, processed in zip(positions, processed_blocks):
            result[pos:pos+len(processed)] = processed
        
        return bytes(result)
    
    async def process_blocks_async(self,
                                  data: bytes,
                                  block_size: int,
                                  process_func: Callable[[bytes], bytes]) -> bytes:
       
        loop = asyncio.get_event_loop()
        
        # Подготовка блоков
        blocks = []
        positions = []
        for i in range(0, len(data), block_size):
            blocks.append(data[i:i+block_size])
            positions.append(i)
        
        # Асинхронная обработка в потоках
        tasks = []
        for block in blocks:
            task = loop.run_in_executor(self.executor, process_func, block)
            tasks.append(task)
        
        processed_blocks = await asyncio.gather(*tasks)
        
        # Сборка результата
        result = bytearray(len(data))
        for pos, processed in zip(positions, processed_blocks):
            result[pos:pos+len(processed)] = processed
        
        return bytes(result)
    
    def process_file_parallel(self,
                             input_file: str,
                             output_file: str,
                             process_func: Callable[[bytes], bytes],
                             chunk_size: int = 64 * 1024) -> None:
       
        from .file_handler import FileHandler
        
        chunks = []
        for chunk in FileHandler.read_chunks(input_file, chunk_size):
            chunks.append(chunk)
        
        # Параллельная обработка частей
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            processed_chunks = list(executor.map(process_func, chunks))
        
        # Запись результата
        FileHandler.write_chunks(output_file, processed_chunks)
    
    def __del__(self):
        self.executor.shutdown(wait=False)
