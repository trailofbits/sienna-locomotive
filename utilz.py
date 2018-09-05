## @package utilz
# basic miscellaneous utilities
import re


## strips out characters in a string that could be harmful for filenames or paths
# @param s strings to sanitize
# @return sanitized string
def sanitizeString(s):
    ret = re.sub(r"[^a-zA-Z0-9._]+", "_", s)
    return re.sub(r"_+", "_", ret)
