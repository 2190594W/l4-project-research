"""
Decrypt & Encrypt Tools module
"""

#pylint: disable=E0401
import pyopenabe

def create_cpabe_instance(master_public_key):
    """Generate CPABE instance for encryption & decryption.

    Parameters
    ----------
    MASTER_PUBLIC_KEY : Bytes
        Bytes object representing the `MASTER_PUBLIC_KEY` to be imported.

    Returns
    -------
    PyABEContext
        Instance of the PyABEContext class, for ciphertext (CP) ABE.

    """
    openabe = pyopenabe.PyOpenABE()
    cpabe = openabe.CreateABEContext("CP-ABE")
    cpabe.importPublicParams(master_public_key)
    # del openabe
    return openabe, cpabe

def process_key_decrypt(key):
    """Read the Bytes from the key file.
    Extract the username from the key filename.

    Parameters
    ----------
    key : FileStorage
        FileStorage object representing the `key` to decrypt file.

    Returns
    -------
    BytesIO, BytesIO, string
        BytesIO object representing the contents of the `key`.
        String representing the username of the `key` file.

    """
    key_bytes = key.read().strip()
    username = key.filename.split('.')[0]
    return key_bytes, username
