import time

from src.implementation import util

READER_INDEX = 0


def main():
    connection = util.get_connection(READER_INDEX)

    # SELECT AID
    select_application_capdu = bytes([
        0x00, 0xa4, 0x04, 0x00, 0x10, 0xa0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00,
        0x00, 0x01, 0x00
    ])
    util.send_command(connection, select_application_capdu)

    read_start = time.time()
    # Select personal data file with FID 0x5000
    header = bytes([0x00, 0xA4, 0x01, 0x0C])
    data = bytes([0x02, 0x50, 0x00])
    command = header + data
    util.send_command(connection, command)

    for i in range(1, 16):
        FID = bytes([0x50, i])
        read_entry(connection, FID)

    read_end = time.time()
    print("Time for reading personal data file: " + str(read_end - read_start) + " s")


def read_entry(connection, FID):
    # Select entry with FID
    header = bytes([0x00, 0xA4, 0x01, 0x0C])
    data = bytes([len(FID)]) + FID
    command = header + data
    util.send_command(connection, command)

    # Read binary
    header = bytes([0x00, 0xB0, 0x00, 0x00])
    le = bytes([0x00])

    command = header + le
    response = util.send_command(connection, command)
    print("Entry with FID " + util.bh(FID) + ": " + response.decode())


if __name__ == '__main__':
    main()
