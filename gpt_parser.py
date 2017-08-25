
'''
Author: Andrey Polovinkin

This program is free software; you can redistribute it and/or
modify it under the terms of MIT License.

Example of command:
$ python gpt_parser.py FILE_PATH
'''

import sys
import struct

def main():
    if len(sys.argv) == 1:
        print("Press input file name!")
        return

    with open(sys.argv[1], "rb") as file:
        if parse_protective_mbr(file) == False:
            return

        number_partition_entry = parse_primary_gpt_header(file)
        if number_partition_entry == 0:
            return

        if parse_partition_entries(file, number_partition_entry) == False:
            return


def parse_protective_mbr(file):
    mbr_data = file.read(512)
    if len(mbr_data) < 512:
        print("ERROR: error read MBR!")
        return False

    position = 446
    number_partition = 0

    while number_partition < 4:
        print('==== Partition {}===='.format(number_partition+1))

        parse_partition_entry(mbr_data[position:position+16])

        number_partition += 1
        position += 16


    return True


def parse_partition_entry(data):
    fields = struct.unpack('<BBBBBBBBLL', data)

    sector = fields[2]
    cylinder = fields[3]
    
    print("Status of physical drive: {}".format(fields[0]))
    print("CHS address: head: {} sector: {} cylinder: {}"
        .format(fields[1], fields[2] & 0x3F, cylinder_format(fields[2], fields[3])))
    print("Partition type: {}".format(fields[4]))
    print("CHS address: head: {} sector: {} cylinder: {}"
        .format(fields[5], fields[6] & 0x3F, cylinder_format(fields[6], fields[7])))
    print("LBA: {}".format(fields[8]))
    print("Number of sectors in partition: {}".format(fields[9]))
    print('\n')    


def cylinder_format(part1, part2):
    return ((part1 & 0xC0) << 2) | part2


def parse_primary_gpt_header(file):
    gpt_header = file.read(512)
    if len(gpt_header) < 512:
        print("ERROR: error read GPT header")
        return 0

    fields = struct.unpack('<8cBBBBLLLQQQQIHHH6BQLLL420c', gpt_header)

    print("==== Primary GPT header ====")
    print("Signature: {}".format(''.join(fields[0:8])))
    print("Revision: {} {} {} {}".format(fields[8], fields[9], fields[10], fields[11]))
    print("Header size: {}".format(fields[12]))
    print("CRC32: {:x}".format(fields[13]))
    print("Reserved: {}".format(fields[14]))
    print("Current LBA: {}".format(fields[15]))
    print("Backup LBA: {}".format(fields[16]))
    print("First usable LBA: {}".format(fields[17]))
    print("Last usable LBA: {}".format(fields[18]))
    print("Disk GUID: {}".format(guid_format(fields[19:29]))) #format(fields[19], fields[20]))
    print("Starting LBA: {}".format(fields[29]))
    print("Number of partition entries: {}".format(fields[30]))
    print("Size of partition entry: {}".format(fields[31]))
    print("CRC32: {:x}".format(fields[32]))
    print("\n")

    return fields[30]


def parse_partition_entries(file, number_partition_entry):

    partition_entry = 0
    while partition_entry < number_partition_entry:
        field_data = file.read(128)
        if len(field_data) < 128:
            print("ERROR: error read {} partition entry".format(partition_entry))
            return False

        if all(ord(x) == 0 for x in field_data):
            return True

        print("==== Partition entry {} ====".format(partition_entry))
        parse_gpt_partition_entry(field_data)
        partition_entry += 1

    return True


def parse_gpt_partition_entry(data):
    fields = struct.unpack('<IHHH6BIHHH6BQQQ72c', data)

    print("Partition type GUID: {}".format(guid_format(fields[0:10])))
    print("Unique partition GUID: {}".format(guid_format(fields[10:20])))
    print("First LBA: {}".format(fields[20]))
    print("Last LBA: {}".format(fields[21]))
    print("Attribute flags: {}".format(fields[22]))
    print("Partition name: {}".format(''.join(fields[23:])))
    print("\n")


def guid_format(guid):
    return '{:08x}-{:04x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}'.format(
        guid[0], guid[1], guid[2], guid[3], 
        guid[4], guid[5], guid[6], guid[7], guid[8], guid[9])


if __name__ == '__main__':
	main()
