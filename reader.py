import struct
from stream_binary_reader import StreamBinaryReader
from encryption import create_cipher, decrypt_data
from compression import decompress_data
from data_structures import DataCenterNode, DataCenterAddress

class DataCenterHeader:
    def read(self, reader, strict):
        # Lecture des 32 premiers octets comme en-tête
        header_data = reader.read_bytes(32)
        print("En-tête:")
        print(f"Données brutes: {header_data.hex()}")
        self.version = reader.read_uint32()
        self.timestamp = reader.read_double()
        self.revision = reader.read_uint32()
        self.unknown1 = reader.read_int16()
        self.unknown2 = reader.read_int16()
        self.unknown3 = reader.read_int32()
        self.unknown4 = reader.read_int32()
        self.unknown5 = reader.read_int32()

class DataCenterKeys:
    def __init__(self):
        self.keys = []
        
    def read(self, reader, architecture):
        # Try to find a valid magic number within the next few bytes
        valid_magic_found = False
        original_position = reader.offset
        
        for i in range(8):  # Try up to 8 different positions
            magic = reader.peek_uint32()
            print(f"Checking magic at offset {reader.offset}: 0x{magic:08X}")
            
            # Check if magic number looks reasonable (less than 10000)
            if 0 < magic < 10000:
                valid_magic_found = True
                break
                
            reader.skip(1)
            
        if not valid_magic_found:
            reader.offset = original_position  # Reset position
            # Try alternative approach - assume small number
            count = reader.read_uint32() & 0xFFFF  # Take only lower 16 bits
            if count > 10000:
                count = count & 0xFF  # Try even smaller number if still too large
        else:
            count = reader.read_uint32()
        
        print(f"Final key count: {count}")
        
        if count == 0 or count > 10000:
            raise ValueError(f"Invalid key count: {count}")
            
        try:
            self.keys = []
            for i in range(count):
                if not reader.can_read(4):
                    break
                key = reader.read_uint32()
                self.keys.append(key)
                if i < 5:  # Debug first few keys
                    print(f"Key {i}: 0x{key:08X}")
                    
        except EOFError as e:
            if len(self.keys) == 0:
                raise ValueError("No valid keys could be read") from e
            print(f"Warning: Only read {len(self.keys)} of {count} keys")
            
        print(f"Successfully read {len(self.keys)} keys")
        return len(self.keys) > 0

    def populate(self):
        # Implémentation de populate si nécessaire
        pass

    def get_keys(self, index):
        if 0 <= index < len(self.keys):
            return self.keys[index]
        return None

class DataCenterStringTable:
    def __init__(self, segment_size):
        self.segment_size = segment_size
        self.strings = []

    def read(self, reader, architecture, strict):
        count = reader.read_uint32()
        self.strings = [reader.read_string() for _ in range(count)]

    def get_string(self, index):
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""

class DataCenterSegmentedRegion:
    def __init__(self):
        self.regions = []

    def read(self, reader, architecture):
        count = reader.read_uint32()
        print(f"Lecture de {count} segments")
        
        if count > 1000:  # Limite raisonnable
            raise ValueError(f"Trop de segments: {count}")
            
        self.regions = [[] for _ in range(count)]
        
        for i in range(count):
            segment_size = reader.read_uint32()
            print(f"Segment {i}: {segment_size} éléments")
            
            if segment_size > 100000:  # Limite raisonnable
                raise ValueError(f"Segment trop grand: {segment_size}")
                
            for _ in range(segment_size):
                # Lecture des données du segment
                # À adapter selon votre format de données
                self.regions[i].append(self.read_segment_data(reader, architecture))

    def read_segment_data(self, reader, architecture):
        # À implémenter selon votre format de données
        pass

class DataCenterFooter:
    def read(self, reader, strict):
        self.marker = reader.read_int32()


class DataCenterAddress:
    def __init__(self, segment, offset):
        self.segment = segment
        self.offset = offset

    def __str__(self):
        return f"Segment: {self.segment}, Offset: {self.offset}"


class DataCenterReader:
    def __init__(self, options):
        self.options = options
        self._header = DataCenterHeader()
        self._keys = DataCenterKeys()
        self._attributes = DataCenterSegmentedRegion()
        self._nodes = DataCenterSegmentedRegion()
        self._values = DataCenterStringTable(1024)
        self._names = DataCenterStringTable(512)
        self._footer = DataCenterFooter()

    def read(self, file_path):
        print(f"Reading file: {file_path}")
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            print(f"Length of encrypted data: {len(encrypted_data)}")
            
            cipher = create_cipher(self.options['key'], self.options['iv'])
            decrypted_data = decrypt_data(cipher, encrypted_data)
            print(f"Decryption successful")
            
            decompressed_data = decompress_data(decrypted_data)
            print(f"Decompressed data (first 100 bytes):", decompressed_data[:100])
            
            return self.parse_data(decompressed_data)

    def parse_data(self, data):
        reader = StreamBinaryReader(data)
        architecture = self.options['architecture']
        strict = self.options['strict']

        print("\n=== Début de l'analyse ===")
        print(f"Taille totale des données : {len(data)} octets")
        
        try:
            print("\n--- Lecture de l'en-tête ---")
            self._header.read(reader, strict)
            
            print(f"\n--- Lecture des clés (position: {reader.offset}) ---")
            reader.debug_state()
            self._keys.read(reader, architecture)
            
            print(f"\n--- Lecture des attributs (position: {reader.offset}) ---")
            reader.debug_state()
            self._attributes.read(reader, architecture)
            
            print(f"\n--- Lecture des nœuds (position: {reader.offset}) ---")
            reader.debug_state()
            self._nodes.read(reader, architecture)
            
            print(f"\n--- Lecture des valeurs (position: {reader.offset}) ---")
            reader.debug_state()
            self._values.read(reader, architecture, strict)
            
            print(f"\n--- Lecture des noms (position: {reader.offset}) ---")
            reader.debug_state()
            self._names.read(reader, architecture, strict)
            
            print("\n--- Population des clés ---")
            self._keys.populate()
            
            print("\n--- Lecture du pied de page ---")
            self._footer.read(reader, strict)

            print("\n--- Création de l'arbre ---")
            root = self.create_node(DataCenterAddress(0, 0), None)
            if root is None:
                raise ValueError("Échec de la création du nœud racine")
            
            return root

        except Exception as e:
            print("\n!!! Erreur durant l'analyse !!!")
            print(f"Position actuelle: {reader.offset}")
            reader.debug_state()
            raise


    def create_node(self, address, parent):
        if address.segment >= len(self._nodes.regions) or address.offset >= len(self._nodes.regions[address.segment]):
            print(f"Adresse invalide: {address}")
            return None

        try:
            node_data = self._nodes.regions[address.segment][address.offset]
            
            # Créer le nœud avec ses propriétés de base
            node = {
                'name': self._names.get_string(node_data.name_id) if hasattr(node_data, 'name_id') else '',
                'attributes': {},
                'children': []
            }

            # Ajouter les attributs
            if hasattr(node_data, 'attributes'):
                for attr in node_data.attributes:
                    if attr.key < len(self._keys.keys):
                        key = self._keys.keys[attr.key]
                        value = self._values.get_value(attr.value) if hasattr(attr, 'value') else None
                        node['attributes'][key] = value

            # Récursivement créer les nœuds enfants
            if hasattr(node_data, 'children'):
                for child_address in node_data.children:
                    child_node = self.create_node(child_address, node)
                    if child_node:
                        node['children'].append(child_node)

            return node

        except Exception as e:
            print(f"Erreur lors de la création du nœud à l'adresse {address}: {str(e)}")
            return None

    def get_string(self, string_id):
        """Récupère une chaîne de caractères à partir de son ID"""
        try:
            if string_id >= 0 and string_id < len(self._values.strings):
                return self._values.strings[string_id]
            return f"<invalid string id: {string_id}>"
        except Exception as e:
            return f"<error: {str(e)}>"

    def read_attributes(self, raw, node):
        for i in range(raw.attribute_count):
            addr = DataCenterAddress(raw.attribute_address.segment_index, 
                                   raw.attribute_address.element_index + i)
            attr = self._attributes.get_element(addr)
            if attr:
                name = self._names.get_string(attr.name_index - 1)
                if name != "value":
                    node.attributes[name] = self.get_attribute_value(attr)
                else:
                    node.value = self.get_attribute_value(attr)

    def read_children(self, raw, parent):
        for i in range(raw.child_count):
            addr = DataCenterAddress(raw.child_address.segment_index,
                                   raw.child_address.element_index + i)
            child = self.create_node(addr, parent)
            if child:
                parent.children.append(child)

    def get_attribute_value(self, attr):
        type_code = attr.type_info & 0x3
        ext_code = (attr.type_info & 0xFFFC) >> 2

        if type_code == 1:  # Integer/Boolean
            if ext_code == 0:
                return attr.value
            elif ext_code == 1:
                return bool(attr.value)
        elif type_code == 2:  # Float
            return struct.unpack('f', struct.pack('I', attr.value))[0]
        elif type_code == 3:  # String
            addr = DataCenterAddress(attr.value & 0xFFFF, (attr.value >> 16) & 0xFFFF)
            return self._values.get_string(addr.element_index)
        return None