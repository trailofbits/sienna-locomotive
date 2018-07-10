from enum import IntEnum


class Mode(IntEnum):
    """ Function selection modes. KEEP THIS UP-TO-DATE with common/enums.h """
    MATCH_INDEX = 1 << 0
    MATCH_RETN_ADDRESS = 1 << 1
    MATCH_ARG_HASH = 1 << 2
