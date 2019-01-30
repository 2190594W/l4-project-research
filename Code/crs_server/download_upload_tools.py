"""
Download & Upload Tools module
"""

import re
import base64

def filename_from_attachment(response):
    """Extract the filename of an attachment from the request,
    using the Content-Disposition header of the HTTP headers.

    Parameters
    ----------
    response : Response (requests lib)
        A Response object from the requests lib with a file as attachment `response`.

    Returns
    -------
    string
        String representing the filename of the attachment.

    """
    if "Content-Disposition" in response.headers:
        res_content_disp = response.headers["Content-Disposition"]
        return re.findall("filename=(.+)", res_content_disp)[0]
    return None


def extract_policy(file_bytes):
    """Function to extract the policy of an encrypted resource,
    directly from the ciphertext. Since the policy is not encrypted
    but stored in plaintext.
    Requires decoding the base64 bytes and using regex to extract
    the policy text.

    Parameters
    ----------
    file_bytes : Bytes
        Bytes object representing the ciphertext file `file_bytes`.

    Returns
    -------
    string (utf-8)
        String representing the policy the resource was encrypted with.

    """
    file_contents = base64.b64decode(file_bytes)
    re_policy = re.findall(br"(?:policy\W+ )(.+)(?:\W\/\W)", file_contents)
    policy = re_policy[0].decode("utf-8")
    return policy

def extract_user_attrs(key_bytes):
    """Function to extract the user's attributes from a user key,
    directly from the ciphertext. Since the user's attributes are
    not encrypted but stored in plaintext, within the file.
    Requires decoding the base64 bytes and using regex to extract
    the user's attributes text.

    Parameters
    ----------
    key_bytes : Bytes
        Bytes object representing the ciphertext file `key_bytes`.

    Returns
    -------
    user_attrs : string (utf-8)
        String representing the user's attributes.

    """
    file_contents = base64.b64decode(key_bytes)
    re_attrs = re.findall(br"(?:input\W+ *\|)(.*)(?:\|$)", file_contents)
    user_attrs = re_attrs[0].decode("utf-8")
    return user_attrs
