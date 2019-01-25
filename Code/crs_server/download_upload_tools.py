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
    res_content_disp = response.headers["Content-Disposition"]
    return re.findall("filename=(.+)", res_content_disp)[0]


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
