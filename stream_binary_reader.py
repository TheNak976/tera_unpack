import struct

class StreamBinaryReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.length = len(data)

    def peek_bytes(self, length):
        """Lit des octets sans avancer le pointeur"""
        if self.offset + length > self.length:
            raise EOFError(f"Tentative de lecture au-delà de la fin du flux: position {self.offset}, demandé {length} octets, disponible {self.length - self.offset}")
        
        return self.data[self.offset:self.offset + length]

    def read_bytes(self, length):
        if self.offset + length > self.length:
            raise EOFError(f"Tentative de lecture au-delà de la fin du flux: position {self.offset}, demandé {length} octets, disponible {self.length - self.offset}")
        
        result = self.data[self.offset:self.offset + length]
        if len(result) != length:
            raise EOFError(f"Données incomplètes: attendu {length} octets, lu {len(result)} octets")
        
        self.offset += length
        return result

    def can_read(self, length):
        return self.offset + length <= self.length

    def read_byte(self):
        return self.read_bytes(1)[0]

    def read_sbyte(self):
        return struct.unpack('b', self.read_bytes(1))[0]

    def read_uint16(self):
        return struct.unpack('<H', self.read_bytes(2))[0]

    def read_int16(self):
        return struct.unpack('<h', self.read_bytes(2))[0]

    def read_uint32(self):
        try:
            data = self.read_bytes(4)
            if len(data) != 4:
                raise struct.error("Données insuffisantes pour uint32")
            return struct.unpack('<I', data)[0]
        except Exception as e:
            print(f"Erreur lecture uint32 à l'offset {self.offset}: {str(e)}")
            print(f"Données disponibles: {len(self.data) - self.offset} octets")
            raise

    def read_int32(self):
        return struct.unpack('<i', self.read_bytes(4))[0]

    def read_uint64(self):
        return struct.unpack('<Q', self.read_bytes(8))[0]

    def read_int64(self):
        return struct.unpack('<q', self.read_bytes(8))[0]

    def read_single(self):
        return struct.unpack('<f', self.read_bytes(4))[0]

    def read_double(self):
        return struct.unpack('<d', self.read_bytes(8))[0]

    def read_string(self):
        result = []
        while self.can_read(2):  # Vérifie s'il y a assez de données pour un caractère
            char = self.read_uint16()
            if char == 0:
                break
            result.append(chr(char))
        return ''.join(result)

    def read_until_null(self):
        """Lit les octets jusqu'à trouver un octet nul"""
        result = bytearray()
        while self.can_read(1):
            byte = self.read_byte()
            if byte == 0:
                break
            result.append(byte)
        return bytes(result)

    def seek(self, offset):
        """Déplace le pointeur à la position spécifiée"""
        if offset < 0 or offset > self.length:
            raise ValueError(f"Position invalide: {offset}")
        self.offset = offset

    def skip(self, count):
        if count < 0:
            raise ValueError("Impossible de reculer dans le flux")
        if self.offset + count > self.length:
            raise EOFError(f"Impossible d'avancer de {count} octets, fin du flux atteinte")
        self.offset += count

    def peek_uint32(self):
        if not self.can_read(4):
            return None
        current_offset = self.offset
        try:
            value = self.read_uint32()
            self.offset = current_offset
            return value
        except:
            self.offset = current_offset
            return None

    def debug_state(self):
        """Affiche l'état actuel du lecteur pour le débogage"""
        print(f"Position actuelle: {self.offset}/{self.length}")
        print(f"Octets disponibles: {self.length - self.offset}")
        if self.can_read(16):
            print(f"Prochains octets: {self.data[self.offset:self.offset+16].hex()}")