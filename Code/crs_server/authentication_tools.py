"""
Authentication Tools module
"""
import re
from urllib.parse import urlparse, urljoin
from flask import request, flash

def is_safe_url(target):
    """Validates if a 'next' url is safe to process.

    Parameters
    ----------
    target : string
        String representing the `target` url.

    Returns
    -------
    Boolean
        True or false if url is safe or not.

    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def validate_passwd(passwd):
    """Verify the strength of 'passwd'
    Returns a boolean indicating if password meets criteria
    A password is considered strong if:
        12 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more

    Parameters
    ----------
    passwd : string
        String of `passwd` to check.

    Returns
    -------
    boolean
        Returns True/False if password is good or not.

    """

    # calculating the length
    if len(passwd) < 12:
        flash('Password must be at least 12 characters long!', 'warning')
        len_error = True
    else:
        len_error = False
    # searching for digits
    if re.search(r"\d", passwd) is None:
        flash('Password must contain at least 1 number!', 'warning')
        digit_error = True
    else:
        digit_error = False
    # searching for uppercase
    if re.search(r"[A-Z]", passwd) is None:
        flash('Password must contain at least 1 uppercase character!', 'warning')
        upper_error = True
    else:
        upper_error = False
    # searching for lowercase
    if re.search(r"[a-z]", passwd) is None:
        flash('Password must contain at least 1 lowercase character!', 'warning')
        lower_error = True
    else:
        lower_error = False
    # searching for symbols
    if re.search(r"\W", passwd) is None:
        flash('Password must contain at least 1 special character!', 'warning')
        symbol_error = True
    else:
        symbol_error = False

    # overall result
    return not (len_error or digit_error or upper_error or lower_error or symbol_error)
