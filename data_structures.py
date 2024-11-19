from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Dict, Any

# Constants
class DataCenterConstants:
    NAME_TABLE_SIZE = 65536
    VALUE_TABLE_SIZE = 65536
    VALUE_ATTRIBUTE_NAME = "__value__"
    ROOT_NODE_NAME = "__root__"

# Type Definitions
class DataCenterTypeCode(IntEnum):
    INTEGER = 0
    BOOLEAN = 1 
    FLOAT = 2
    STRING = 3

@dataclass
class DataCenterAddress:
    segment_index: int
    element_index: int

# Raw Data Structures
@dataclass 
class DataCenterRawAttribute:
    name_index: int
    type_info: int
    value: int

@dataclass
class DataCenterRawNode:
    name_index: int
    keys_info: int
    attribute_count: int
    child_count: int
    attribute_address: DataCenterAddress
    child_address: DataCenterAddress

# Table Classes
class DataCenterStringTable:
    def __init__(self, max_size: int):
        self._strings: List[str] = []
        self._max_size = max_size
        
    def read(self, reader, architecture: str, strict: bool = False) -> None:
        count = reader.read_int32()
        if strict and (count < 0 or count > self._max_size):
            raise ValueError(f"Invalid string count: {count}")
            
        for _ in range(count):
            length = reader.read_int32()
            if length < 0:
                print(f"Warning: Invalid string length: {length}")
                continue
            string_data = reader.read_bytes(length)
            try:
                self._strings.append(string_data.decode('utf-8'))
            except UnicodeDecodeError:
                print(f"Warning: Invalid string data")
                self._strings.append('')

    def get_string(self, index: int) -> str:
        if 0 <= index < len(self._strings):
            return self._strings[index]
        return ''

class DataCenterKeys:
    def __init__(self, names_table: DataCenterStringTable):
        self._names = names_table
        self._keys: Dict[int, List[str]] = {}
        
    def read(self, reader, architecture: str) -> None:
        count = reader.read_int32()
        if count < 0:
            print(f"Warning: Invalid key count: {count}")
            return
            
        for _ in range(count):
            key_id = reader.read_int32()
            name_count = reader.read_int32()
            
            if name_count < 0:
                print(f"Warning: Invalid name count for key {key_id}")
                continue
                
            names = []
            for _ in range(name_count):
                name_index = reader.read_int32() - 1
                if name_index >= 0:
                    names.append(self._names.get_string(name_index))
                    
            self._keys[key_id] = names

    def get_keys(self, key_id: int) -> List[str]:
        return self._keys.get(key_id, [])

# Segmented Region
class DataCenterSegmentedRegion:
    def __init__(self, element_type: Any):
        self._segments: List[List[Any]] = []
        self._element_type = element_type
        
    def read(self, reader, architecture: str) -> None:
        segment_count = reader.read_int32()
        if segment_count < 0:
            print(f"Warning: Invalid segment count: {segment_count}")
            return
            
        for _ in range(segment_count):
            element_count = reader.read_int32()
            if element_count < 0:
                print(f"Warning: Invalid element count: {element_count}")
                continue
                
            segment = []
            for _ in range(element_count):
                if self._element_type == DataCenterRawAttribute:
                    element = self._read_attribute(reader)
                elif self._element_type == DataCenterRawNode:
                    element = self._read_node(reader)
                else:
                    raise ValueError(f"Unknown element type: {self._element_type}")
                segment.append(element)
            self._segments.append(segment)
                
    def _read_attribute(self, reader) -> DataCenterRawAttribute:
        return DataCenterRawAttribute(
            name_index=reader.read_int32(),
            type_info=reader.read_int32(),
            value=reader.read_int32()
        )
        
    def _read_node(self, reader) -> DataCenterRawNode:
        return DataCenterRawNode(
            name_index=reader.read_int32(),
            keys_info=reader.read_int32(),
            attribute_count=reader.read_int32(),
            child_count=reader.read_int32(),
            attribute_address=DataCenterAddress(
                reader.read_uint16(),
                reader.read_uint16()
            ),
            child_address=DataCenterAddress(
                reader.read_uint16(),
                reader.read_uint16()
            )
        )

    def get_element(self, address: DataCenterAddress) -> Any:
        if 0 <= address.segment_index < len(self._segments):
            segment = self._segments[address.segment_index]
            if 0 <= address.element_index < len(segment):
                return segment[address.element_index]
        return None