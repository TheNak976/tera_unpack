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
    def __init__(self, name, value=None, keys=None, attributes=None, children=None, parent=None):
        self.parent = parent
        self.name = name
        self.value = value
        self.keys = keys if keys is not None else []
        self.attributes = attributes if attributes is not None else {}
        self.children = children if children is not None else []

    def add_child(self, child_node):
        child_node.parent = self
        self.children.append(child_node)

    def add_attribute(self, key, value):
        self.attributes[key] = value

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

    def sort_children(self, key=None, reverse=False):
        self.children.sort(key=key, reverse=reverse)

    def __repr__(self):
        return f"DataCenterNode(name={self.name}, value={self.value}, attributes={self.attributes}, children={len(self.children)})"