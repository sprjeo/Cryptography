import asyncio
from rc4.file_encryptor import encrypt_or_decrypt_file

KEY = b"secret_key"

async def main():

    await encrypt_or_decrypt_file(
        "data/original.txt",
        "data/encrypted.bin",
        KEY
    )

    await encrypt_or_decrypt_file(
        "data/encrypted.bin",
        "data/decrypted.txt",
        KEY
    )
    print('done')

if __name__ == "__main__":
    asyncio.run(main())
