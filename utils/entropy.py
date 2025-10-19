#Implements computing Shanon's entropy of bytes or strings

import math
from typing import Union

def shannon_entropy(data: Union[bytes, str]) -> float:
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode()

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    total = len(byte)
    entropy = 0.0
    for count in freq.values():
        p = count/total
        entropy -= p * math.log2(p)

    return entropy

def combined_entropy(*nonces: bytes) -> float:
    combined = b''.join(nonces)
    return shannon_entropy(combined)