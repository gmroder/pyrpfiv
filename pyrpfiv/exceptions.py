class PyrpfivError(Exception):
    """Base exception class for pyrpfiv."""
    pass


class AESKeyExtractionError(PyrpfivError):
    """Exception raised when AES key extraction fails."""
    pass


class TOCDecryptionError(PyrpfivError):
    """Exception raised when TOC decryption fails."""
    pass


class RPFParsingError(PyrpfivError):
    """Exception raised when parsing the RPF file fails."""
    pass


class FileExtractionError(PyrpfivError):
    """Exception raised when file extraction fails."""
    pass


class FileNotFoundInRPFError(PyrpfivError):
    """Exception raised when a file is not found in the RPF archive."""
    pass


class HashesFileNotFoundError(PyrpfivError):
    """Exception raised when the 'hashes.ini' file is not found."""
    pass


class InvalidTOCEntryError(PyrpfivError):
    """Exception raised when a TOC entry is invalid."""
    pass


class InvalidEntryTypeError(PyrpfivError):
    """Exception raised when an entry type is invalid."""
    pass
