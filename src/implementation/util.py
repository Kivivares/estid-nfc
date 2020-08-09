from smartcard.CardConnection import CardConnection
from smartcard.System import readers
import time


def get_connection(reader_index):
    r = readers()
    print(r)
    connection = r[reader_index].createConnection()
    connection.connect(CardConnection.T1_protocol)
    return connection


def send_command(connection, command_apdu):
    print("### C-APDU: " + bh(command_apdu))
    start = time.time()
    data, sw1, sw2 = connection.transmit(list(command_apdu))
    end = time.time()
    data = bytes(data)

    print("    R-APDU: " + bh(data) + bh(bytes([sw1])) + bh(bytes([sw2])))
    print("    Time: " + str(end - start) + " s")
    return bytearray(data)


def bh(bytes):
    return bytes.hex().upper()
