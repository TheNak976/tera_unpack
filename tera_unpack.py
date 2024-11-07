from encryption import create_cipher, decrypt_data
from reader import DataCenterReader
from compression import decompress_data

# Options de configuration pour DataCenterReader
options = {
    'key': '1C01C904FF76FF06C211187E197B5716',  # clé de chiffrement en hexadécimal
    'iv': '396C342C52A0C12D511DD0209F90CA7D',    # IV en hexadécimal
    'architecture': 'x64',       # ou 'x86' selon votre architecture
    'strict': True
}

# Chemin vers le fichier de données que vous souhaitez analyser
file_path = 'C:/Users/acyho/Downloads/data/DataCenter_Final_EUR.dat'

# Initialisation et utilisation de DataCenterReader
reader = DataCenterReader(options)

# Create the cipher for decryption
cipher = create_cipher(options['key'], options['iv'])

# Read the encrypted data
with open(file_path, 'rb') as f:
    encrypted_data = f.read()

# Check the length of the encrypted data
print(f"Length of encrypted data: {len(encrypted_data)}")

# Decrypt the data
decrypted_data = decrypt_data(cipher, encrypted_data)
print("Decrypted data (first 100 bytes):", decrypted_data[:100])


print(f"Premiers octets du fichier chiffré: {encrypted_data[:16].hex()}")
print(f"Premiers octets après déchiffrement: {decrypted_data[:16].hex()}")

# Debug supplémentaire
print(f"Format d'en-tête: {decrypted_data[4:6].hex()}")
print(f"Marqueur début données: {decrypted_data[6:10].hex()}")



with open('debug_decrypted.bin', 'wb') as f:
    f.write(decrypted_data[:1024])  # Sauvegarde les 1024 premiers octets pour analyse
print(f"Signature des données: {decrypted_data[:8].hex()}")

# Decompress the decrypted data
decompressed_data = decompress_data(decrypted_data)
print("Decompressed data (first 100 bytes):", decompressed_data[:100])

# Process the decompressed data as needed
root_node = reader.parse_data(decompressed_data)

# Affichage des informations du noeud racine
print(f"Root Node Name: {root_node.name}")
print(f"Root Node Value: {root_node.value}")
print(f"Root Node Attributes: {root_node.attributes}")
print(f"Root Node Children: {[child.name for child in root_node.children]}")