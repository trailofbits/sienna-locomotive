## @package utilz
# basic miscellaneous utilities
import re


## strips out characters in a string that could be harmful for filenames or paths
# @param s strings to sanitize
# @return sanitized string
def sanitizeString(s):
    ret = s
    ret = re.sub( r"[^a-zA-Z0-9\._]+", "_", ret )
    ret = re.sub( r"_+", "_", ret )
    return s