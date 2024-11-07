import zlib
import struct
from io import BytesIO

def decompress_data(data):
    try:
        # Lecture de la taille décompressée
        uncompressed_size = struct.unpack('<I', data[:4])[0]
        print(f"Taille attendue après décompression: {uncompressed_size}")
        
        # Analyse de l'en-tête
        header_bytes = data[4:6]
        print(f"En-tête compression: {header_bytes.hex()}")
        
        # Les données commencent après l'en-tête
        compressed_data = data[6:]
        print(f"Taille données compressées: {len(compressed_data)}")
        
        # Construction d'un en-tête zlib valide
        zlib_header = bytearray([0x78, 0x9C])
        
        # Calcul Adler32 pour le footer
        adler32 = zlib.adler32(b'') & 0xffffffff
        footer = struct.pack('>I', adler32)
        
        # Assemblage des données avec en-tête et footer corrects
        processed_data = zlib_header + compressed_data + footer
        
        # Tentative de décompression avec plusieurs configurations
        methods = [
            (processed_data, dict(wbits=15)),
            (compressed_data, dict(wbits=-15)),
            (data[4:], dict(wbits=-15)),
            (compressed_data, dict(wbits=31)),
            (compressed_data, dict(wbits=47))
        ]
        
        for input_data, kwargs in methods:
            try:
                result = zlib.decompress(input_data, **kwargs)
                if len(result) == uncompressed_size:
                    return result
                print(f"Taille incorrecte: {len(result)} vs {uncompressed_size}")
            except zlib.error as e:
                print(f"Tentative échouée: {str(e)}")
                continue
        
        # Si toutes les tentatives échouent, essayons de décompresser bloc par bloc
        output = bytearray(uncompressed_size)
        output_pos = 0
        
        block_size = 8192  # 8KB blocks
        overlap = 1024    # 1KB overlap
        
        for i in range(0, len(compressed_data), block_size - overlap):
            block = compressed_data[i:i + block_size]
            if not block:
                break
                
            try:
                dec = zlib.decompressobj(wbits=-15)
                chunk = dec.decompress(block)
                if chunk:
                    size = min(len(chunk), uncompressed_size - output_pos)
                    output[output_pos:output_pos + size] = chunk[:size]
                    output_pos += size
                    
                    if output_pos >= uncompressed_size:
                        break
            except:
                continue
        
        if output_pos > 0:
            return bytes(output[:output_pos])
            
        raise ValueError("Échec de toutes les méthodes de décompression")
        
    except Exception as e:
        print(f"Erreur critique: {str(e)}")
        print(f"Premiers octets: {data[:32].hex()}")
        raise ValueError(f"Échec de la décompression: {str(e)}")