from Crypto.Cipher import AES
# Remove unused import
# from Crypto.Util.Padding import unpad

def create_cipher(key, iv):
    key_bytes = bytes.fromhex(key)  # Convert key to bytes
    iv_bytes = bytes.fromhex(iv)    # Convert iv to bytes
    return AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

def decrypt_data(cipher, data):
    if not data:
        raise ValueError("Input data is empty")
    
    original_length = len(data)
    # Pad to block size if needed
    if len(data) % AES.block_size != 0:
        padded_length = len(data) + (AES.block_size - len(data) % AES.block_size)
        data = data.ljust(padded_length, b'\0')
    
    try:
        # Decrypt padded data
        decrypted = cipher.decrypt(data)
        # Trim result back to original size
        decrypted = decrypted[:original_length]
        print("Decryption successful")
        return decrypted
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")