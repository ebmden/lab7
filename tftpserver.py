"""
- NOTE: REPLACE 'N' Below with your section, year, and lab number
- CS2911 - 011
- Fall 2021
- Lab 7
- Names:
  - Eden Basso
  - Lucas Gral

A Trivial File Transfer Protocol Server

Introduction: (Describe the lab in your own words)




Summary: (Summarize your experience with the lab, what you learned, what you liked,what you disliked, and any suggestions you have for improvement)





"""

# import modules -- not using "from socket import *" in order to selectively use items with "socket." prefix
import socket
import os
import math

# Helpful constants used by TFTP
TFTP_PORT = 69
TFTP_BLOCK_SIZE = 512  # needs to handle when packet % 512 = 0
MAX_UDP_PACKET_SIZE = 65536


def main():
    """
    Processes a single TFTP request
    """

    client_socket = socket_setup()

    print("Server is ready to receive a request")

    ####################################################
    # Your code starts here                            #
    #   Be sure to design and implement additional     #
    #   functions as needed                            #
    ####################################################

    # create client socket
    # recieve message from client in
    # still needs to close the server socket

    # get opcode, filename, and mode from RRQ
    # send
    # get ACK opcode:04 Block#:00
    # get



    ####################################################
    # Your code ends here                              #
    ####################################################

    client_socket.close()


def get_file_block_count(filename):
    """
    Determines the number of TFTP blocks for the given file
    :param filename: THe name of the file
    :return: The number of TFTP blocks for the file or -1 if the file does not exist
    """
    try:
        # Use the OS call to get the file size
        #   This function throws an exception if the file doesn't exist
        file_size = os.stat(filename).st_size
        return math.ceil(file_size / TFTP_BLOCK_SIZE)
    except:
        return -1


def get_file_block(filename, block_number):
    """
    Get the file block data for the given file and block number
    :param filename: The name of the file to read
    :param block_number: The block number (1 based)
    :return: The data contents (as a bytes object) of the file block
    """
    file = open(filename, 'rb')
    block_byte_offset = (block_number-1) * TFTP_BLOCK_SIZE
    file.seek(block_byte_offset)
    block_data = file.read(TFTP_BLOCK_SIZE)
    file.close()
    return block_data


def put_file_block(filename, block_data, block_number):
    """
    Writes a block of data to the given file
    :param filename: The name of the file to save the block to
    :param block_data: The bytes object containing the block data
    :param block_number: The block number (1 based)
    :return: Nothing
    """
    file = open(filename, 'wb')
    block_byte_offset = (block_number-1) * TFTP_BLOCK_SIZE
    file.seek(block_byte_offset)
    file.write(block_data)
    file.close()

# Server
def socket_setup():
    """
    Sets up a UDP socket to listen on the TFTP port
    :return: The created socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', TFTP_PORT))
    return s


####################################################
# Write additional helper functions starting here  #
####################################################


def receive_packets(client_socket):
    """
    Receives and handles packets from client such as RRQ, ACK, and ERROR
    :return: dictionary with parsed through bytes
    :rtype: dictionary
    :author: Eden Basso
    """
    # recv packet from client
    (packet, client_address) = client_socket.recvfrom(MAX_UDP_PACKET_SIZE)
    # get opcode of packet - 1st 2 bytes
    opcode = packet[0] + packet[1]
    # based on opcode determine which protocol to use to pasrse through packet
    method_call = {b'\x30\x31': parse_rrq,
                   b'\x30\x34': parse_ack,
                   b'\x30\x35': parse_error}
    field_dict = method_call[opcode](packet, opcode)
    # return dict *to be used by main()*
    return field_dict


def parse_rrq(packet, opcode):
    """
    Parses through Read Request field and adds bytes to dictionary
    :param packet: what has been determined to be the RRQ sent as a packet from the client
    :type packet: bytes
    :param opcode: 2 bytes that indicate what field and therefore what protocol to use to parse through bytes
    :type opcode: bytes
    :return: Opcode, Filename, and Mode
    :rtype: dictionary
    :author: Eden Basso
    """
    # (2)op | Filename | (1)0 | Mode | (2)00
    # copy bytes to dict
    rqq_bytes = dict()
    rqq_bytes['Opcode'] = opcode

    # starting at index 2 -> 1 null byte to indc end of  filename
    end_filename = packet.find(b'\x00')
    rqq_bytes['Filename'] = packet[2:end_filename]
    packet_sliced = packet[end_filename + 1:]  # slice this tho get the index to find mode
    rqq_bytes['Mode'] = packet_sliced[end_filename + 1:packet.find(b'\x00\x00')]

    return rqq_bytes


def parse_ack(packet, opcode):
    """
    Parses through Acknowledgment field and adds bytes to dictionary
    :param packet: what has been determined to be the ACK sent as a packet from the client
    :type packet: bytes
    :param opcode: 2 bytes that indicate what field and therefore what protocol to use to parse through bytes
    :type opcode: bytes
    :return: Opcode and associated Block #
    :rtype: dictionary
    :author: Eden Basso
    """
    ack_bytes = {'Opcode': opcode, 'Block #': packet[2] + packet[3]}
    return ack_bytes


def parse_error(packet, opcode):
    """
    Parses through Error field and adds bytes to dictionary
    :param packet: what has been determined to be the ERROR sent as a packet from the client
    :type packet: bytes
    :param opcode: 2 bytes that indicate what field and therefore what protocol to use to parse through bytes
    :type opcode: bytes
    :return: Opcode, ErrorCode, and Error Message
    :rtype: dictionary
    :author: Eden Basso
    """
    error_bytes = dict()
    error_bytes['Opcode'] = opcode
    end_message = packet.find(b'\x00')
    error_bytes['Error Code'] = packet[2:end_message]
    packet_sliced = packet[end_message + 1:]
    error_bytes['Error Message'] = packet_sliced[end_message +1:packet.find(b'\x00\x00')]
    return error_bytes


main()

