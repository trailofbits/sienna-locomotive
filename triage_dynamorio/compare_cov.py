import sys
import struct

if __name__ == '__main__':
    f1 = sys.argv[1]
    f2 = sys.argv[2]

    with open(f1, 'rb') as f:
        c1 = f.read()

    s1 = set()
    for i in range(0, len(c1), 8):
        if i + 8 > len(c1):
            break
        s1.add(struct.unpack('<Q', c1[i:i+8])[0])

    with open(f2, 'rb') as f:
        c2 = f.read()

    s2 = set()
    for i in range(0, len(c2), 8):
        if i + 8 > len(c2):
            break
        s2.add(struct.unpack('<Q', c2[i:i+8])[0])

    print('Unique blocks in s1: ', s1 - s2)
    print('Unique blocks in s2: ', s2 - s1)

