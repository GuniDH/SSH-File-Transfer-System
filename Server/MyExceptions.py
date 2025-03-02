class DuplicateClientError(Exception):
    def __init__(self, message):
        super().__init__(message)

class UnregisteredClientError(Exception):
    def __init__(self, message):
        super().__init__(message)

class DuplicateFileError(Exception):
    def __init__(self, message):
        super().__init__(message)

class InexistentFileError(Exception):
    def __init__(self, message):
        super().__init__(message)
