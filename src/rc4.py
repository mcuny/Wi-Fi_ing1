from binascii import unhexlify
from scapy.utils import hexstr

def rc4(data: bytes, key: bytes)-> str:
    """
    RC4 is a stream cypher.
    There are two parts to the algorithm.
    KSA: Key Scheduling Algorithm
    PRGA: Pseudo Random Generator Algorithm
    The goal here is to build a keystream
    from the key to apply a XOR to the data

    params:
        data: data to decrypt
        key: IV + Wi-Fi password
    returns:
        str: cyphered/decyphered data
    """
    extended_key = KSA(key)
    key_stream = PRGA(extended_key, len(data))
    output = [(b ^ key_stream[i]) for i, b in enumerate(data)]

    return bytearray(output)

def KSA(key: bytes) -> list:
    """
    Key Scheduling algorithm
    is the first process in rc4. It
    returns an 'extended' key which
    has a higher enthropy then the
    simple concatenation.

    params:
        key: IV + Wi-Fi password
    returns:
        list of bytes, 'extended' key
    """
    table = list(range(256))
    y = 0

    for x in range(256):
        y = (y + table[x] + key[x % len(key)]) % 256
        table[x], table[y] = table[y], table[x]

    return table

def PRGA(ext_k: list, l: int) -> bytes:
    """
    Pseudo Random Generator Algorithm
    is the second step in rc4 algorithm.
    It generates one pseudo-random byte
    of the keystream.

    params:
        ext_k: extended key
        l: length of data
    returns:
        KeyStream
    """
    x = y = 0
    res = []

    for i in range(l):
        x = (x + 1) % 256
        y = (y + ext_k[x]) % 256

        ext_k[x], ext_k[y] = ext_k[y], ext_k[x]
        indx = (ext_k[x] + ext_k[y]) % 256
        res.append(ext_k[indx])

    return res

def generate_seed(iv: bytes, pwd: bytes) -> bytes:
    """
    Formats the Wi-Fi password
    and concatenates it to the
    IV.

    params:
        iv: WEP IV
        pwd: wi-fi password
    returns:
        bytes: packet key
    """
    keyLen = len(pwd)
    if keyLen == 5:
        key = unhexlify(hexstr(pwd, onlyhex = 1).replace(' ', ''))
    elif keyLen == 10:
        key = unhexlify(pwd)
    return iv + key
