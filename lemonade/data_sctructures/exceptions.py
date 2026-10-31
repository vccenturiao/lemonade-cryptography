class DataStructureError(Exception):
    """Base exception for data structure errors."""

class EmptyDataStructureError(DataStructureError):
    """Raised when attempting to access or remove an item from an empty data structure."""