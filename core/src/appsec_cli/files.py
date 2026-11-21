"""Read bounded regular files, including on filesystems that allow named pipes."""

import os
import stat


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Expected a bounded regular file.")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("File exceeded its size limit.")
        return raw
