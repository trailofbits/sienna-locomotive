import re

def sanitizeString(s):
    ret = s
    ret = re.sub( r"[^a-zA-Z0-9\._]+", "_", ret )
    ret = re.sub( r"_+", "_", ret )
    return s