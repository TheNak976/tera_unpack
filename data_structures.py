class DataCenterAddress:
    def __init__(self, segment_index, element_index):
        self.segment_index = segment_index
        self.element_index = element_index

class DataCenterRawNode:
    def __init__(self, name_index, keys_info, attribute_count, child_count, attribute_address, child_address):
        self.name_index = name_index
        self.keys_info = keys_info
        self.attribute_count = attribute_count
        self.child_count = child_count
        self.attribute_address = attribute_address
        self.child_address = child_address

class DataCenterRawAttribute:
    def __init__(self, name_index, type_info, value):
        self.name_index = name_index
        self.type_info = type_info
        self.value = value

class DataCenterNode:
    def __init__(self, name, value, keys, attributes, children):
        self.name = name
        self.value = value
        self.keys = keys
        self.attributes = attributes
        self.children = children