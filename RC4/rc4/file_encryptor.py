import asyncio
from .rc4_algorithm import RC4

CHUNK_SIZE = 4096

async def encrypt_or_decrypt_file(input_file, output_file, key: bytes):
    rc4 = RC4(key)
    loop = asyncio.get_running_loop()

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        while True:
            chunk = await loop.run_in_executor(None, fin.read, CHUNK_SIZE)
            if not chunk:
                break
            result = rc4.process(chunk)
            await loop.run_in_executor(None, fout.write, result)
