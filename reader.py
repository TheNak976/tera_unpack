import struct
from data_center_format import DataCenterFormat
from stream_binary_reader import StreamBinaryReader
from encryption import create_cipher, decrypt_data
from compression import decompress_data
from data_structures import (
    DataCenterConstants,
    DataCenterStringTable,
    DataCenterKeys,
    DataCenterSegmentedRegion,
    DataCenterRawAttribute,
    DataCenterRawNode
)


class DataCenterNode:
    def __init__(self, name, value=None, attributes=None, children=None):
        self.name = name
        self.value = value
        self.attributes = attributes or {}
        self.children = children or []
        self.parent = None

        # Validate special attributes
        if value is not None and name != "__value__":
            raise ValueError("Only __value__ nodes can have a value")
            


    def get_key_value(self):
        """Get value of key attributes for sorting"""
        return 0  # Default sort value

    def sort_children(self, key=None, reverse=False):
        """Sort children by name and key attributes"""
        if key is None:
            # Sort by name first, then by key values
            key = lambda x: (x.name, x.get_key_value())
        self.children.sort(key=key, reverse=reverse)

    def add_child(self, child_node):
        self.children.append(child_node)
        child_node.parent = self

    def remove_child(self, child_node):
        if child_node in self.children:
            self.children.remove(child_node)
            child_node.parent = None

    def clear_children(self):
        for child in self.children:
            child.parent = None
        self.children = []

    def reverse_children(self):
        self.children.reverse()

    def add_attribute(self, name, value, type_code=None):
        """Add attribute with validation"""
        if name == VALUE_NODE_NAME and type_code != DataCenterTypeCode.STRING:
            raise ValueError("__value__ attribute must be string type")
        self.attributes[name] = value

    def __repr__(self):
        return f"DataCenterNode(name={self.name}, value={self.value}, attributes={self.attributes}, children={len(self.children)})"


class DataCenterHeader:
    def __init__(self):
        self.version = 0
        self.timestamp = 0.0
        self.revision = 0
        self.unknown_values = [0] * 5

    def read(self, reader):
        """Lit l'en-tête du fichier DC"""
        try:
            # Lecture de la version
            self.version = reader.read_uint32()
            print(f"Version: {hex(self.version)}")

            # Lecture du timestamp
            self.timestamp = reader.read_double()
            print(f"Timestamp: {self.timestamp}")

            # Pour la version 6, lecture de la révision
            if self.version == 6:
                self.revision = reader.read_uint32()
                print(f"Révision: {self.revision}")

            # Lecture des 5 valeurs inconnues
            self.unknown_values[0] = reader.read_int16()  # unknown1
            self.unknown_values[1] = reader.read_int16()  # unknown2
            self.unknown_values[2] = reader.read_int32()  # unknown3
            self.unknown_values[3] = reader.read_int32()  # unknown4
            self.unknown_values[4] = reader.read_int32()  # unknown5

            print("Valeurs inconnues:", [hex(x) for x in self.unknown_values])

        except EOFError as e:
            raise EOFError(f"Erreur lors de la lecture de l'en-tête: {str(e)}")
        except Exception as e:
            raise ValueError(f"Erreur lors de la lecture de l'en-tête: {str(e)}")

    def is_valid(self, strict=True):
        """Vérifie si l'en-tête est valide"""
        # Vérification de la version
        if self.version not in [3, 6]:
            return False

        # Vérification du timestamp en mode strict
        if strict and self.timestamp != -1.0:
            return False

        # En mode strict, toutes les valeurs inconnues doivent être 0
        if strict and any(self.unknown_values):
            return False

        return True

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
    def __init__(self):
        self.strings = []
        self.count = 0

    def read(self, reader):
        """Lit la table des chaînes"""
        try:
            # Lecture du nombre de chaînes
            self.count = reader.read_uint32()
            print(f"Nombre de chaînes: {self.count}")

            if self.count > 1000000:  # Limite raisonnable
                raise ValueError(f"Nombre de chaînes trop élevé: {self.count}")

            # Lecture des offsets
            offsets = []
            last_offset = 0
            for i in range(self.count):
                offset = reader.read_uint32()
                # Validation de l'offset
                if offset < last_offset or offset > reader.length:
                    print(f"Warning: Offset invalide détecté à l'index {i}: {offset}")
                    continue
                offsets.append(offset)
                last_offset = offset

            # Position de départ des données de chaînes
            base_position = reader.offset

            # Lecture des chaînes
            self.strings = []
            for i in range(len(offsets)):
                try:
                    # Calcul de la longueur de la chaîne
                    current_offset = offsets[i]
                    next_offset = offsets[i + 1] if i + 1 < len(offsets) else reader.length - base_position
                    
                    # Validation de la longueur
                    length = next_offset - current_offset
                    if length < 0 or length > 10000:  # Limite raisonnable pour une chaîne
                        print(f"Warning: Longueur de chaîne invalide à l'index {i}: {length}")
                        self.strings.append("")
                        continue

                    # Positionnement au début de la chaîne
                    absolute_position = base_position + current_offset
                    if absolute_position >= reader.length:
                        print(f"Warning: Position invalide pour la chaîne {i}: {absolute_position}")
                        self.strings.append("")
                        continue

                    reader.seek(absolute_position)

                    # Lecture de la chaîne
                    string_data = reader.read_bytes(length)
                    
                    # Troncature au premier octet nul si présent
                    null_pos = string_data.find(b'\0')
                    if (null_pos != -1):
                        string_data = string_data[:null_pos]

                    # Décodage de la chaîne
                    try:
                        string = string_data.decode('utf-8')
                        self.strings.append(string)
                    except UnicodeDecodeError:
                        print(f"Warning: Erreur de décodage UTF-8 pour la chaîne {i}")
                        string = string_data.decode('utf-8', errors='replace')
                        self.strings.append(string)

                except Exception as e:
                    print(f"Warning: Erreur lors de la lecture de la chaîne {i}: {str(e)}")
                    self.strings.append("")  # Chaîne vide en cas d'erreur

            print(f"Lecture de {len(self.strings)} chaînes terminée")

        except EOFError as e:
            raise EOFError(f"Erreur lors de la lecture de la table des chaînes: {str(e)}")
        except Exception as e:
            raise ValueError(f"Erreur lors de la lecture de la table des chaînes: {str(e)}")

    def get_string(self, index):
        """Récupère une chaîne par son index"""
        if not 0 <= index < len(self.strings):
            raise IndexError(f"Index de chaîne invalide: {index}")
        return self.strings[index]

    def __len__(self):
        return len(self.strings)

    def __getitem__(self, index):
        return self.get_string(index)

    def __iter__(self):
        return iter(self.strings)

class DataCenterSegmentedRegion:
    def __init__(self):
        self.segments = []
        self.count = 0

class DataCenterSegmentedRegion:
    def __init__(self):
        self._segments = []

    def read(self, reader, architecture):
        """Lit les segments avec validation améliorée"""
        try:
            position = reader.offset
            print(f"Position avant lecture des segments: {position}")
            
            count = reader.read_int32()
            print(f"Nombre de segments à lire: {count}")
            
            # Validate count
            if count < 0 or count > 1000000:
                print(f"WARNING - Invalid segment count ({count}), using alternate...")
                count = min(abs(count) & 0xFFFF, 1000000)
            
            # Handle 0 count case
            if count == 0:
                print("WARNING - No segments to read")
                self._segments = []
                return
                
            print(f"Final segment count to read: {count}")
            
            # Read segments with limit
            MAX_SEGMENTS = 100000
            read_count = min(count, MAX_SEGMENTS)
            
            segments = []
            for i in range(read_count):
                try:
                    segment = self._read_segment(reader, architecture)
                    if segment:
                        segments.append(segment)
                except Exception as e:
                    print(f"ERROR - Failed to read segment {i}: {e}")
                    continue
                    
            if read_count < count:
                print(f"WARNING - Only read {read_count} of {count} segments")
                
            print(f"Successfully read {len(segments)} valid segments")
            self._segments = segments

        except Exception as e:
            print(f"ERROR - Failed to read segments: {e}")
            self._segments = []

    def _read_attribute_value(self, reader, architecture):
        """Lit la valeur d'un attribut selon son type"""
        try:
            type_code = reader.read_uint16() & 0x3  # Get bottom 2 bits for base type
            extended_code = reader.read_uint16() >> 2  # Get remaining bits
            
            # Read value based on type
            if type_code == 1:  # INT
                if extended_code & 1:  # Boolean
                    return reader.read_uint8() != 0
                return reader.read_int32()
                
            elif type_code == 2:  # FLOAT
                return reader.read_float()
                
            elif type_code == 3:  # STRING
                # Read string address
                segment_index = reader.read_uint16()
                element_index = reader.read_uint16()
                return {
                    'segment_index': segment_index,
                    'element_index': element_index
                }
                
            else:
                print(f"WARNING - Unknown type code: {type_code}")
                return None
                
        except Exception as e:
            print(f"ERROR - Failed to read attribute value: {e}")
            return None


    def _read_segment(self, reader, architecture):
        """Lecture d'un segment individuel"""
        segment = {}
        
        # Lecture des attributs du segment selon l'architecture
        if architecture.lower() == 'x64':
            # Format 64-bits
            segment['child_count'] = reader.read_uint16()
            segment['attribute_count'] = reader.read_uint16()
            segment['child_address'] = self._read_address(reader)
            segment['attribute_address'] = self._read_address(reader)
        else:
            # Format 32-bits
            segment['child_count'] = reader.read_uint16()
            segment['attribute_count'] = reader.read_uint16()
            segment['child_address'] = self._read_address32(reader)
            segment['attribute_address'] = self._read_address32(reader)

        return segment

    def _read_address(self, reader):
        """Lecture d'une adresse 64-bits"""
        return {
            'segment_index': reader.read_uint16(),
            'element_index': reader.read_uint16()
        }

    def _read_address32(self, reader):
        """Lecture d'une adresse 32-bits"""
        return {
            'segment_index': reader.read_uint16(),
            'element_index': reader.read_uint16()
        }

    def get_element(self, address):
        """Récupère un élément à partir de son adresse"""
        if not 0 <= address['segment_index'] < len(self._segments):
            raise IndexError(f"Index de segment invalide: {address['segment_index']}")
            
        segment = self._segments[address['segment_index']]
        if not 0 <= address['element_index'] < segment.get('child_count', 0):
            raise IndexError(f"Index d'élément invalide: {address['element_index']}")
            
        return segment

    def __len__(self):
        return len(self._segments)

    def __getitem__(self, index):
        return self._segments[index]

    def __iter__(self):
        return iter(self._segments)

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
        self.architecture = options.get('architecture', 'x64')
        self.strict = options.get('strict', True)
        self.format = None
        self.timestamp = 0.0
        self.revision = 0
        self._header = DataCenterHeader()
        # Initialize string tables with size limits
        self._names = DataCenterStringTable(DataCenterConstants.NAME_TABLE_SIZE)
        self._values = DataCenterStringTable(DataCenterConstants.VALUE_TABLE_SIZE)
        # Initialize keys with names table reference
        self._keys = DataCenterKeys(self._names)
        # Initialize segmented regions with their respective types
        self._attributes = DataCenterSegmentedRegion(DataCenterRawAttribute)
        self._nodes = DataCenterSegmentedRegion(DataCenterRawNode)
        self._options = options

        # Vérification de l'architecture
        if self.architecture not in ['x86', 'x64']:
            raise ValueError(f"Architecture non supportée: {self.architecture}")
        
        # Initialisation des composants
        self._header = DataCenterHeader()
        self._keys = DataCenterKeys()
        self._nodes = DataCenterSegmentedRegion()
        self._attributes = DataCenterSegmentedRegion()
        self._string_table = DataCenterStringTable()

    def parse_data(self, data):
        if not data:
            raise ValueError("Données vides")

        reader = StreamBinaryReader(data)
        architecture = self.architecture

        print("=== Début de l'analyse ===")
        print(f"Taille totale des données : {len(data)} octets")

        try:
            # Lecture de l'en-tête
            print("\n--- Lecture de l'en-tête ---")
            self._read_header(reader)

            # Lecture de la table des chaînes en premier
            print("\n--- Lecture de la table de chaînes ---")
            self._read_string_table(reader)
            if len(self._string_table) == 0:
                raise ValueError("Table de chaînes vide")

            # Lecture des clés
            print("\n--- Lecture des clés ---")
            self._read_keys(reader)

            # Détermination de la position des nœuds
            node_position = reader.offset
            print(f"\nPosition avant les nœuds: {node_position}")
            print(f"Octets: {reader.peek_bytes(16).hex()}")

            # Lecture des nœuds
            print("\n--- Lecture des nœuds ---")
            self._nodes.read(reader, architecture)
            if len(self._nodes) == 0:
                raise ValueError("Aucun nœud trouvé")

            # Lecture des attributs après avoir vérifié les nœuds
            print("\n--- Lecture des attributs ---")
            self._attributes.read(reader, architecture)

            return self._build_tree()

        except EOFError as e:
            print(f"DEBUG - Position finale: {reader.offset}/{reader.length}")
            raise EOFError(f"Fin de fichier inattendue: {str(e)}")
        except Exception as e:
            print(f"DEBUG - Erreur à la position: {reader.offset}/{reader.length}")
            raise ValueError(f"Erreur lors de l'analyse: {str(e)}")

    def _read_header(self, reader):
        """
        Lit l'en-tête du fichier DataCenter
        
        Args:
            reader: StreamBinaryReader pour lire les données
            
        Returns:
            None
            
        Raises:
            ValueError: Si l'en-tête n'est pas valide
        """
        try:
            # Lecture de la version et détermination du format
            version = reader.read_uint32()
            self.format = DataCenterFormat.get_format(version, self.architecture)
            print(f"Format détecté: {self.format.name}")

            # Lecture du timestamp
            self.timestamp = reader.read_double()
            print(f"Timestamp: {self.timestamp}")

            # Lecture de la révision pour les formats V6
            if self.format.is_v6():
                self.revision = reader.read_uint32()
                print(f"Révision: {self.revision}")
            else:
                self.revision = 0

            # Lecture des valeurs d'en-tête supplémentaires
            self.unknown_value1 = reader.read_int16()
            self.unknown_value2 = reader.read_int16()
            self.unknown_value3 = reader.read_int32()
            self.unknown_value4 = reader.read_int32()
            self.unknown_value5 = reader.read_int32()

            # Vérification de la validité de l'en-tête
            if not self._validate_header():
                raise ValueError("En-tête invalide: valeurs incorrectes")

            print(f"En-tête lu avec succès - Format: {self.format.name}, Révision: {self.revision}")

        except EOFError as e:
            raise ValueError(f"Erreur de lecture de l'en-tête: fin de fichier inattendue - {str(e)}")
        except Exception as e:
            raise ValueError(f"Erreur lors de la lecture de l'en-tête: {str(e)}")

    def _validate_header(self):
        """
        Valide les valeurs de l'en-tête
        
        Returns:
            bool: True si l'en-tête est valide, False sinon
        """
        # Vérification du timestamp en mode strict
        if self.strict and self.timestamp != -1.0:
            print("Avertissement: timestamp invalide en mode strict")
            return False

        # Vérification des valeurs inconnues en mode strict
        if self.strict:
            unknown_values = [
                self.unknown_value1,
                self.unknown_value2,
                self.unknown_value3,
                self.unknown_value4,
                self.unknown_value5
            ]
            if any(unknown_values):
                print("Avertissement: valeurs inconnues non nulles en mode strict")
                return False

        # Si tout est OK
        return True

    def _read_keys(self, reader):
        """Lecture de la table des clés avec validation améliorée"""
        try:
            print(f"Position actuelle: {reader.offset}")
            print(f"Position actuelle: {reader.offset}/{reader.length}")
            print(f"Octets disponibles: {reader.length - reader.offset}")
            print(f"Prochains octets: {reader.peek_bytes(16).hex()}")
            
            # Read key count
            count = reader.read_int32()
            print(f"DEBUG - Raw key count: {count}")
            
            # Validate key count
            if count < 0 or count > 1000000:
                print(f"WARNING - Invalid key count ({count}), adjusting...")
                count = min(abs(count) & 0xFFFF, 1000000)
                
            print(f"DEBUG - Adjusted key count: {count}")
            
            # Handle case of 0 keys
            if count == 0:
                print("WARNING - No keys found, creating default empty key")
                # Create default key with all fields set to 0
                default_key = {
                    'name_index_1': 0,
                    'name_index_2': 0,
                    'name_index_3': 0,
                    'name_index_4': 0
                }
                self._keys = [default_key]
                return
                
            # Read keys
            keys = []
            for i in range(count):
                try:
                    key = {
                        'name_index_1': reader.read_uint16(),
                        'name_index_2': reader.read_uint16(),
                        'name_index_3': reader.read_uint16(),
                        'name_index_4': reader.read_uint16()
                    }
                    keys.append(key)
                    print(f"DEBUG - Read key {i}: {key}")
                except Exception as e:
                    print(f"ERROR - Failed to read key {i}: {e}")
                    break
                    
            self._keys = keys or [default_key]  # Fallback to default if no keys read
            print(f"Successfully read {len(self._keys)} keys")
            
        except Exception as e:
            print(f"ERROR - Failed to read keys: {e}")
            # Create default key as fallback
            self._keys = [{
                'name_index_1': 0,
                'name_index_2': 0,
                'name_index_3': 0,
                'name_index_4': 0
            }]

    def _read_string_table(self, reader):
        """Lecture de la table des chaînes avec support UTF-16"""
        # Initialize with special names (index 0 is empty, 1 is __root__, 2 is __value__)
        strings = ['', ROOT_NODE_NAME, VALUE_NODE_NAME]
        
        try:
            string_count = reader.read_int32()
            print(f"Nombre de chaînes déclaré: {string_count}")
            
            # Validation de la taille
            if string_count < 0 or string_count > 1000000:
                print(f"Warning: Nombre de chaînes suspect ({string_count}), ajustement...")
                string_count = min(string_count & 0xFFFF, 1000000)
            
            for i in range(string_count):
                try:
                    offset = reader.read_int32()
                    if offset < 0:
                        print(f"Warning: Offset négatif détecté à l'index {i}: {offset}")
                        continue
                        
                    length = reader.read_int32()
                    if length < 0 or length > 1000000:
                        print(f"Warning: Longueur invalide à l'index {i}: {length}")
                        continue
                    
                    # Lecture des données en UTF-16
                    data = reader.read_bytes(length * 2)  # UTF-16 = 2 bytes per char
                    try:
                        string = data.decode('utf-16-le')  # TERA uses little endian
                        strings.append(string)
                        print(f"DEBUG - Read string[{i}]: '{string}'")
                    except UnicodeDecodeError:
                        print(f"Warning: Erreur de décodage UTF-16 pour la chaîne {i}")
                        strings.append(f"[Invalid UTF-16 string {i}]")
                except Exception as e:
                    print(f"Erreur lors de la lecture de la chaîne {i}: {e}")
                    print(f"DEBUG - Current reader position: {reader.offset}")
                    break
                    
            print(f"Nombre de chaînes lues avec succès: {len(strings)}")
            print(f"DEBUG - First 5 strings: {strings[:5]}")
            
        except Exception as e:
            print(f"Error reading string table: {e}")
            # Ensure we at least have the special names
            strings = ['', ROOT_NODE_NAME, VALUE_NODE_NAME]
            
        self._string_table = strings
        self.dump_string_table()

    def _build_tree(self):
        """Build tree with improved validation"""
        try:
            # Initialize root node
            root = DataCenterNode(name=ROOT_NODE_NAME)
            
            if not self._nodes:
                raise ValueError("No nodes found")
                    
            first_node = self._nodes[0]
            print(f"DEBUG - Raw first node: {first_node}")
            
            # Normalize node structure
            normalized_node = {
                'name_index': 1,  # Index for __root__ in string table
                'child_count': first_node.get('child_count', 0),
                'attribute_count': first_node.get('attribute_count', 0),
                'child_address': self._validate_address(first_node.get('child_address')),
                'attribute_address': self._validate_address(first_node.get('attribute_address'))
            }
            
            print(f"DEBUG - Normalized node: {normalized_node}")
            
            # Process children
            if normalized_node['child_count'] > 0:
                child_addr = normalized_node['child_address']
                print(f"DEBUG - Processing children at address: {child_addr}")
                self._process_children(root, child_addr, normalized_node['child_count'])
                
            return root

        except Exception as e:
            print(f"DEBUG - Error in _build_tree: {str(e)}")
            raise


    def _validate_address(self, addr):
        """Validate and normalize address"""
        if not isinstance(addr, dict) or 'segment_index' not in addr or 'element_index' not in addr:
            return {'segment_index': 0, 'element_index': 0}
        return {
            'segment_index': max(0, min(addr['segment_index'], len(self._nodes)-1)),
            'element_index': max(0, addr['element_index'])
        }

    def _process_children(self, parent, address, count):
        """Process child nodes"""
        print(f"DEBUG - Processing {count} children at {address}")
        try:
            for i in range(count):
                child_index = address['segment_index'] + i
                if child_index < len(self._nodes):
                    child_node = self._nodes[child_index]
                    self._process_node(parent, child_node)
        except Exception as e:
            print(f"DEBUG - Error processing children: {e}")


    def _get_name(self, name_index):
        """Get name from name index with validation"""
        try:
            if not name_index or name_index <= 0:
                return None
                
            # Check if index is within bounds of string table
            if name_index >= len(self._strings):
                print(f"WARNING: Name index {name_index} out of bounds")
                return None
                
            name = self._strings[name_index]
            print(f"DEBUG - Name lookup: index={name_index}, name={name}")
            return name
        except Exception as e:
            print(f"DEBUG - Error getting name: {str(e)}")
            return None

    def _process_node(self, parent_node, raw_node):
        """Process node according to specification"""
        try:
            name_index = raw_node.get('name_index')
            if not name_index or name_index <= 0:
                print(f"Debug - Invalid name index in node: {raw_node}")
                return

            node = DataCenterNode(
                name=self._get_name(name_index),
                value=raw_node.get('value')
            )

            attributes = raw_node.get('attributes', [])
            sorted_attrs = sorted(attributes, key=lambda x: x['name_index'])
            for attr in sorted_attrs:
                self._process_attribute(node, attr)

            children = raw_node.get('children', [])
            for child in children:
                self._process_node(node, child)
            node.sort_children()

            parent_node.children.append(node)

        except Exception as e:
            print(f"Error processing node: {e}")
            raise


    def _process_attribute(self, node, raw_attr):
        """Process attribute with proper typing"""
        name_index = raw_attr.get('name_index')
        if not name_index or name_index <= 0:
            return

        name = self._get_name(name_index)
        type_code = raw_attr.get('type_code')
        value = raw_attr.get('value')

        if name == VALUE_NODE_NAME:
            if type_code != DataCenterTypeCode.STRING:
                raise ValueError("__value__ attribute must be string type")
            node.value = value
        else:
            node.attributes[name] = value


    def _process_attribute_value(self, attr):
        """Traitement de la valeur d'un attribut selon son type"""
        type_info = attr['type_info']
        value = attr['value']

        # Type 1: booléen
        if type_info == 1:
            return bool(value)
        # Type 2: entier
        elif type_info == 2:
            return value
        # Type 3: flottant
        elif type_info == 3:
            return float(value)
        # Type 4: chaîne
        elif type_info == 4:
            return self._string_table.get_string(value)
        else:
            raise ValueError(f"Type d'attribut inconnu: {type_info}")

    def get_string(self, index):
        """Récupération d'une chaîne dans la table des chaînes"""
        return self._string_table.get_string(index)
    
    def dump_string_table(self):
        """Affiche les premières chaînes de la table pour debug"""
        print("\nDump de la table des chaînes:")
        for i, string in enumerate(self._string_table):
            if i < 10:  # Affiche les 10 premières chaînes
                print(f"String[{i}] = {repr(string)}")

    def _read_node_segments(self, reader):
        """Lecture des segments de nœuds"""
        segment_count = reader.read_int32()
        print(f"Nombre initial de segments: {segment_count}")
        
        # Validation et correction
        if segment_count < 0 or segment_count > 1000000:
            corrected_count = segment_count & 0xFFFF
            print(f"Correction du nombre de segments: {corrected_count}")
            segment_count = corrected_count
        
        segments = []
        for i in range(segment_count):
            try:
                segment = self._read_node_segment(reader)
                segments.append(segment)
            except Exception as e:
                print(f"Erreur lors de la lecture du segment {i}: {e}")
                break
                
        print(f"Segments lus avec succès: {len(segments)}")
        return segments