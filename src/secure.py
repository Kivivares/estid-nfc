import time

from src.implementation import pace, secureMessaging, util

PASSWORD = "000000"  # CAN
READER_INDEX = 2


def main():
    connection = util.get_connection(READER_INDEX)

    pace_start = time.time()
    session_keys = pace.establish(connection, PASSWORD)
    if session_keys is None:
        print("Failed to perform PACE")
        exit()
    pace_end = time.time()
    print("PACE time: " + str(pace_end - pace_start) + " s")

    Kenc, Kmac = session_keys
    SSC = 0

    print("Kenc: " + util.bh(Kenc))
    print("Kmac: " + util.bh(Kmac))

    read_start = time.time()
    # Select personal data file with FID 0x5000
    header = bytes([0x00, 0xA4, 0x01, 0x0C])
    data = bytes([0x50, 0x00])

    print(util.bh(header + data))
    SSC += 1
    wrapped = secureMessaging.wrap(Kenc, Kmac, SSC, header, data, None)
    util.send_command(connection, wrapped)
    SSC += 1

    for i in range(1, 16):
        FID = bytes([0x50, i])
        SSC = read_entry(connection, Kenc, Kmac, SSC, FID)

    read_end = time.time()
    print("Time for reading personal data file: " + str(read_end - read_start) + " s")


def read_entry(connection, Kenc, Kmac, SSC, FID):
    # Select entry with FID
    header = bytes([0x00, 0xA4, 0x01, 0x0C])
    data = FID
    SSC += 1
    print(util.bh(header + data))
    wrapped = secureMessaging.wrap(Kenc, Kmac, SSC, header, data, None)
    util.send_command(connection, wrapped)
    SSC += 1

    # Read binary
    header = bytes([0x00, 0xB0, 0x00, 0x00])
    le = bytes([0x00])
    SSC += 1
    print(util.bh(header + data))
    wrapped = secureMessaging.wrap(Kenc, Kmac, SSC, header, None, le)
    response = util.send_command(connection, wrapped)
    SSC += 1
    unwrapped = secureMessaging.unwrap(Kenc, SSC, response)
    unpadded = secureMessaging.remove_padding(unwrapped)

    print("Entry with FID " + util.bh(FID) + ": " + unpadded.decode())

    return SSC


if __name__ == '__main__':
    main()
