import hashlib
import os

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point

from src.implementation import util

PASSWORD_REFERENCE = 2  # CAN
ALGORITHM_OID = [0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04]  # PACE-ECDH-GM-AES-CBC-CMAC-256


def establish(connection, password):
    # SELECT AID
    select_application_capdu = bytes([
        0x00, 0xa4, 0x04, 0x00, 0x10, 0xa0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00,
        0x00, 0x01, 0x00
    ])
    util.send_command(connection, select_application_capdu)

    # Send MSE: SET AT
    mse_set_at_capdu = bytes(
        [0x00, 0x22, 0xc1, 0xa4, len(ALGORITHM_OID) + 5, 0x80, len(ALGORITHM_OID)]
        + ALGORITHM_OID
        + [0x83, 0x01, PASSWORD_REFERENCE]
    )
    util.send_command(connection, mse_set_at_capdu)

    # GET NONCE
    get_nonce_capdu = bytes([0x10, 0x86, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00])
    get_nonce_rapdu = util.send_command(connection, get_nonce_capdu)

    # Decrypt nonce
    encrypted_nonce = get_nonce_rapdu[4:]
    decrypted_nonce = decrypt_nonce(encrypted_nonce, password)

    # Establish elliptic curve
    curve = NIST256p.curve
    standard_base_point = NIST256p.generator.to_affine()
    order = standard_base_point.order()

    # Map nonce
    mapped_base_point = map_nonce(connection, decrypted_nonce, curve, standard_base_point, order)

    # Key agreement
    private_key, public_key = generate_key_pair(mapped_base_point)
    uncompressed_public_key = encode_uncompressed_point(public_key)

    # Sending command for key agreement
    perform_key_agreement_dad = build_dynamic_authentication_data(bytes([0x83]), uncompressed_public_key)
    perform_key_agreement_capdu = bytes([0x10, 0x86, 0x00, 0x00, len(perform_key_agreement_dad)]) + \
                                  perform_key_agreement_dad + bytes([0x00])
    perform_key_agreement_rapdu = util.send_command(connection, perform_key_agreement_capdu)

    chip_uncompressed_point = perform_key_agreement_rapdu[4:]
    chip_public_key = decode_uncompressed_point(chip_uncompressed_point, curve, order)

    calculated_secret_point = chip_public_key * int.from_bytes(private_key, 'big')
    shared_secret = calculated_secret_point.x().to_bytes(32, byteorder='big')

    # Deriving session keys
    Kenc = hashlib.sha256(shared_secret + b"\x00\x00\x00\x01").digest()

    Kmac = hashlib.sha256(shared_secret + b"\x00\x00\x00\x02").digest()

    # Calculating authentication token MACs
    terminal_authentication_token_MAC = calculate_authentication_token(Kmac, chip_uncompressed_point)
    calculated_chip_authentication_token_MAC = calculate_authentication_token(Kmac, uncompressed_public_key)
    mutual_authentication_dad = build_dynamic_authentication_data(bytes([0x85]), terminal_authentication_token_MAC)
    mutual_authentication_capdu = bytes([0x00, 0x86, 0x00, 0x00, len(mutual_authentication_dad)]) + \
                                  mutual_authentication_dad + bytes([0x00])
    mutual_authentication_rapdu = util.send_command(connection, mutual_authentication_capdu)

    received_chip_authentication_token_MAC = mutual_authentication_rapdu[4:]

    if (received_chip_authentication_token_MAC == calculated_chip_authentication_token_MAC):
        return (Kenc, Kmac)
    else:
        print("PACE failed")
        return None


def map_nonce(connection, decrypted_nonce, curve, standard_base_point, order):
    private_key, public_key = generate_key_pair(standard_base_point)
    private_key = private_key
    encoded_public_key = encode_uncompressed_point(public_key)

    # Sending the command
    map_nonce_dad = build_dynamic_authentication_data(bytes([0x81]), encoded_public_key)
    map_nonce_capdu = bytes([0x10, 0x86, 0x00, 0x00, len(map_nonce_dad)]) + map_nonce_dad + bytes([0x00])
    map_nonce_rapdu = util.send_command(connection, map_nonce_capdu)
    chip_uncompressed_point = map_nonce_rapdu[4:]

    chip_public_key = decode_uncompressed_point(chip_uncompressed_point, curve, order)
    shared_secret = chip_public_key * int.from_bytes(private_key, 'big')

    mapped_base_point = standard_base_point * int.from_bytes(decrypted_nonce, 'big') + shared_secret
    return mapped_base_point


def generate_key_pair(base_point):
    private_key = os.urandom(32)
    public_key = base_point * int.from_bytes(private_key, 'big')

    return private_key, public_key


def decrypt_nonce(encrypted_nonce, password):
    decryption_key = hashlib.sha256(password.encode() + b"\x00\x00\x00\x03").digest()
    iv = 16 * b'\x00'
    aes = AES.new(decryption_key, AES.MODE_CBC, iv)
    return aes.decrypt(encrypted_nonce)


def encode_uncompressed_point(point):
    return bytes([0x04]) + point.x().to_bytes(32, byteorder='big') + point.y().to_bytes(32, byteorder='big')


def decode_uncompressed_point(bytes, curve, order):
    x = int.from_bytes(bytes[1:33], 'big')
    y = int.from_bytes(bytes[33:65], 'big')

    return Point(curve, x, y, order)


def build_dynamic_authentication_data(tag, data):
    return bytes([0x7C, len(data) + 2]) + tag + bytes([len(data)]) + data


def calculate_authentication_token(Kmac, public_key):
    public_point = bytes([0x86, len(public_key)]) + public_key
    oid = bytes([0x06, len(ALGORITHM_OID)] + ALGORITHM_OID)
    input_data = bytes([0x7f, 0x49, len(oid) + len(public_point)]) + oid + public_point

    cmac = CMAC.new(Kmac, ciphermod=AES)
    cmac.update(input_data)
    return cmac.digest()[:8]
