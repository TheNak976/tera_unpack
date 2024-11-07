import struct
from data_center_format import DataCenterFormat
from stream_binary_reader import StreamBinaryReader
from encryption import create_cipher, decrypt_data
from compression import decompress_data
from data_structures import DataCenterNode, DataCenterAddress

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

    def read(self, reader, architecture):
        # Lecture du nombre de segments
        count = reader.read_uint32()
        
        print(f"Position avant lecture des segments: {reader.offset}")
        print(f"Nombre de segments à lire: {count}")
        
        # More robust validation with recovery attempts
        if count > 1000000:  # If count is too large
            # Try reading as 16-bit value
            reader.seek(reader.offset - 4)  # Go back 4 bytes
            count = reader.read_uint16()
            print(f"Attempting with 16-bit count: {count}")
            
            if count > 100000:  # Still too large
                # Try next 16 bits
                count = reader.read_uint16()
                print(f"Attempting with next 16-bit count: {count}")
                
                if count > 100000:  # If still invalid
                    # Try using a reasonable default based on file size
                    count = min(10000, (reader.length - reader.offset) // 16)
                    print(f"Using estimated count based on file size: {count}")
        
        if count == 0:
            # Try reading next value as potential count
            next_count = reader.peek_uint32() & 0xFFFF  # Take only lower 16 bits
            if 0 < next_count < 100000:
                print(f"Using alternative count: {next_count}")
                reader.skip(4)
                count = next_count
            else:
                raise ValueError(f"Invalid segment count: {count}")
        
        # Debug info
        print(f"Final segment count to read: {count}")
        
        self.segments = []
        self.count = count

        # Read segments with additional validation
        valid_segments = 0
        for i in range(count):
            try:
                if not reader.can_read(8):  # Minimum size for a segment
                    print(f"Cannot read more segments, stopping at {i}")
                    break
                    
                segment = self._read_segment(reader, architecture)
                
                # Basic validation of segment data
                if (segment['child_count'] < 1000000 and 
                    segment['attribute_count'] < 1000000 and
                    segment['child_address']['segment_index'] < 100000 and
                    segment['attribute_address']['segment_index'] < 100000):
                    self.segments.append(segment)
                    valid_segments += 1
                else:
                    print(f"Skipping invalid segment at index {i}")
                    
                if valid_segments >= 100000:  # Safety limit
                    print("Reached maximum segment limit")
                    break
                    
            except EOFError:
                print(f"Reached EOF at segment {i}")
                break
            except Exception as e:
                print(f"Error reading segment {i}: {e}")
                break
        
        print(f"Successfully read {valid_segments} valid segments")
        return valid_segments > 0

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
        if not 0 <= address['segment_index'] < len(self.segments):
            raise IndexError(f"Index de segment invalide: {address['segment_index']}")
            
        segment = self.segments[address['segment_index']]
        if not 0 <= address['element_index'] < segment.get('child_count', 0):
            raise IndexError(f"Index d'élément invalide: {address['element_index']}")
            
        return segment

    def __len__(self):
        return len(self.segments)

    def __getitem__(self, index):
        return self.segments[index]

    def __iter__(self):
        return iter(self.segments)

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
        self.unknown_value1 = 0
        self.unknown_value2 = 0
        self.unknown_value3 = 0
        self.unknown_value4 = 0
        self.unknown_value5 = 0

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
        """Lecture de la table des clés"""
        print(f"Position actuelle: {reader.offset}")
        print(f"Position actuelle: {reader.offset}/{reader.length}")
        print(f"Octets disponibles: {reader.length - reader.offset}")
        print(f"Prochains octets: {reader.peek_bytes(16).hex()}")
        
        self._keys.read(reader, self.architecture)

    def _read_string_table(self, reader):
        """Lecture de la table des chaînes"""
        # Sauvegarde de la position actuelle
        original_pos = reader.offset
        
        try:
            self._string_table.read(reader)
        except Exception as e:
            # En cas d'erreur, on essaie de lire à partir du prochain alignement 4 octets
            print(f"Première tentative échouée: {e}")
            reader.seek(original_pos + (4 - (original_pos % 4)))
            print(f"Nouvelle tentative à la position {reader.offset}")
            self._string_table.read(reader)

    def _build_tree(self):
        """Construction de l'arbre à partir des données lues"""
        # Création du nœud racine
        root = DataCenterNode(name="DataCenter", value=None)
        
        # Lecture du premier nœud (index 0)
        try:
            first_node = self._nodes[0]
            self._process_node(root, first_node)
        except IndexError:
            raise ValueError("Pas de nœud racine trouvé")
        
        return root

    def _process_node(self, parent_node, raw_node):
        """Traitement récursif des nœuds avec gestion améliorée des erreurs et validations"""
        try:
            # Validation et lecture du nom du nœud
            if 'name_index' not in raw_node:
                raise ValueError("Le nœud n'a pas de name_index")
                
            try:
                name = self._string_table.get_string(raw_node['name_index'])
                if not name:
                    raise ValueError(f"name_index invalide: {raw_node['name_index']}")
                parent_node.name = name
            except Exception as e:
                print(f"Avertissement: Impossible de lire le nom du nœud (index={raw_node['name_index']}): {e}")
                parent_node.name = f"UnknownNode_{raw_node['name_index']}"

            # Validation des adresses et compteurs
            max_element_index = len(self._attributes) - 1 if self._attributes else 0
            attr_start = raw_node['attribute_address']['element_index']
            attr_count = raw_node['attribute_count']

            if attr_start + attr_count > max_element_index:
                print(f"Avertissement: Nombre d'attributs ajusté de {attr_count} à {max_element_index - attr_start}")
                attr_count = max(0, max_element_index - attr_start)

            # Lecture des attributs
            for i in range(attr_count):
                addr = raw_node['attribute_address']
                attr_addr = {
                    'segment_index': addr['segment_index'],
                    'element_index': addr['element_index'] + i
                }
                
                try:
                    attr = self._attributes.get_element(attr_addr)
                    if attr is None:
                        raise ValueError(f"Attribut non trouvé à l'adresse {attr_addr}")

                    name = self._string_table.get_string(attr['name_index'])
                    if not name:
                        raise ValueError(f"Nom d'attribut invalide (index={attr['name_index']})")

                    value = self._process_attribute_value(attr)
                    parent_node.attributes[name] = value
                except Exception as e:
                    print(f"Erreur lors de la lecture de l'attribut {i}: {e}")

            # Validation et lecture des nœuds enfants
            max_node_index = len(self._nodes) - 1 if self._nodes else 0
            child_start = raw_node['child_address']['element_index']
            child_count = raw_node['child_count']

            if child_start + child_count > max_node_index:
                print(f"Avertissement: Nombre d'enfants ajusté de {child_count} à {max_node_index - child_start}")
                child_count = max(0, max_node_index - child_start)

            # Lecture des enfants
            for i in range(child_count):
                addr = raw_node['child_address']
                child_addr = {
                    'segment_index': addr['segment_index'],
                    'element_index': addr['element_index'] + i
                }
                
                try:
                    child_raw = self._nodes.get_element(child_addr)
                    if child_raw is None:
                        raise ValueError(f"Nœud enfant non trouvé à l'adresse {child_addr}")

                    child_node = DataCenterNode()
                    self._process_node(child_node, child_raw)
                    parent_node.children.append(child_node)
                    child_node.parent = parent_node  # Établir la relation parent-enfant
                except Exception as e:
                    print(f"Erreur lors de la lecture du nœud enfant {i} (adresse={child_addr}): {e}")

            # Gestion des clés si présentes
            if 'keys_info' in raw_node:
                try:
                    keys = self._keys.get_keys((raw_node['keys_info'] & 0b1111111111110000) >> 4)
                    if keys:
                        parent_node.keys = keys
                except Exception as e:
                    print(f"Erreur lors de la lecture des clés: {e}")

        except Exception as e:
            print(f"Erreur critique lors du traitement du nœud: {e}")
            # On conserve le nœud même en cas d'erreur pour maintenir la structure
            if not parent_node.name:
                parent_node.name = "ErrorNode"

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