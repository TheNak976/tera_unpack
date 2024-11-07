class DataCenterFormat:
    @staticmethod
    def get_format(version, architecture):
        # Simple format object with name property
        class Format:
            def __init__(self, name):
                self.name = name
            def is_v6(self):
                return 'V6' in self.name

        if version == 3:
            return Format(f"V3_{architecture}")
        elif version == 6:
            return Format(f"V6_{architecture}")
        else:
            raise ValueError(f"Unsupported version: {version}")