from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC


def wrap(k_enc, k_mac, ssc, header, data, le):
    ssc = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ssc])
    masked_header = bytes([0x0C])
    masked_header += header[1:4]

    do87 = b''
    if data is not None:
        data = pad_data(data)
        encrypted_data = encrypt(k_enc, ssc, data)
        do87 = bytes([0x87, len(encrypted_data) + 1, 0x01]) + encrypted_data

    do97 = b''
    if le is not None:
        do97 = bytes([0x97, 0x01]) + le

    padded_masked_header = pad_data(masked_header)
    mac_data = ssc + padded_masked_header + do87 + do97
    padded_mac_data = pad_data(mac_data)

    cmac = CMAC.new(k_mac, ciphermod=AES)
    cmac.update(padded_mac_data)
    mac = cmac.digest()[:8]

    wrapped = (masked_header +
               bytes([len(do87) + len(mac) + len(do97) + 2]) +
               do87 +
               do97 +
               bytes([0x8E, 0x08]) +
               mac +
               bytes([0]))
    return wrapped


def unwrap(k_enc, ssc, data):
    ssc = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ssc])

    do87 = data[:19]
    do87_data = do87[3:]

    decrypted = decrypt(k_enc, ssc, do87_data)
    return decrypted


def encrypt(key, ssc, plaintext):
    iv = get_iv(key, ssc)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(plaintext)


def get_iv(key, plaintext):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plaintext)


def decrypt(key, ssc, ciphertext):
    iv = get_iv(key, ssc)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(ciphertext)


def pad_data(data):
    data += bytes([0x80])
    while len(data) % 16 != 0:
        data += bytes([0x00])

    return data


def remove_padding(padded_bytes):
    unpadded = b''
    for byte in padded_bytes:
        byte = bytes([byte])
        if byte == bytes([0x80]):
            break
        unpadded += byte

    return unpadded
