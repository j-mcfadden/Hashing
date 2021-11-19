"""
Author: Joshua McFadden
Description:
    A client to communicate with a hashing server, send files and receive a hash
"""
import argparse
import socket
import sys
import os
import ssl

CHUNK_SIZE = 1024


def arg_check(arguments):
    """
    arg_check makes sure that the arguments passed in by the user are valid
    :param arguments: Arguments passed in by the command line
    :return: None
    """
    # Check to see if the IP address is valid
    ip = arguments.IP_Address.split('.')
    if len(ip) != 4:
        print(f'Client: The IP address entered {arguments.IP_Address} is not '
              f'valid please try again')
        sys.exit()
    # For each segment of the IP Address
    for cluster in ip:
        # Check to see if 1 to 3 chars long
        if not ((len(cluster) >= 1) and (len(cluster) <= 3)):
            print(f'Client: The IP address entered {arguments.IP_Address} '
                  f'is not valid please try again')
            sys.exit()
        try:
            # Check if all ints
            if (int(cluster) > 255) and (int(cluster) < 0):
                print(f'Client: The IP address entered {arguments.IP_Address} '
                      f'is not valid please try again')
                sys.exit()
        except TypeError:
            print(f'Client: The IP address entered {arguments.IP_Address} '
                  f'is not valid please try again')

    # Check to see if the files are valid
    if len(arguments.files) == 0:
        print('Client: File not specified in command line, please try again')
        sys.exit()
    for file in arguments.files:
        if not os.path.isfile(file):
            print(f'Client: The file entered "{file}" does not exist '
                  f'please try again')
            sys.exit()

    # Check to see if the port is valid
    if not ((arguments.port > 0) and (arguments.port < 65535)):
        print(f'Client: The Port entered {arguments.port} is not valid please '
              f'try again')

    # All arguments are valid if you get here


def connect(config):
    """
    connect will create the ssl connection to the server for the client to use
    :param config: a tuple
    :return: an ssl socket connected to the server
    """
    print(f'Client: Connecting to {config[0]}:{config[1]}')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ssl_context = ssl.SSLContext()

    ssl_sock = ssl_context.wrap_socket(sock=sock, server_side=False,
                                       server_hostname=config[0],
                                       do_handshake_on_connect=True)

    try:
        ssl_sock.settimeout(10)
        ssl_sock.connect(config)
    except ConnectionRefusedError:
        print(f'Client: Server at {config[0]}:{config[1]} either refused the'
              f' connection or is not up')
        sys.exit()
    except socket.error as error:
        ssl_sock.close()
        raise socket.error(f'Client: Failed creating the connection to the '
                           f'server on {config[0]}:{config[1]}') from error

    return ssl_sock


def prep_data(sock, files):
    """
    prep_data opens the files and sends their content over the network to the
        server. I then sends the file name after the file content has been sent
    :param sock: The socket that has been created for the client to connect to
        the server
    :param files: A list of file to open and send to the server to be hashed
    :return: None
    """
    # Send num of files
    send_data(sock, bytes(str(len(files)).encode()))

    for file_name in files:
        try:
            # Open the file
            with open(file_name, 'rb') as file_pointer:
                while True:
                    # Get a chunk of 4096 bytes
                    file_chunk = file_pointer.read(CHUNK_SIZE)
                    # Send the data
                    send_data(sock, file_chunk)
                    if not file_chunk:
                        break
        except FileNotFoundError as error:
            sock.detach()
            sock.close()
            raise FileNotFoundError(f'Client The file entered {file_name} '
                                    f'does not exist please try again') \
                from error

        # Get the hash from the server
        data = b''
        buffer = recv_data(sock)
        while buffer != b'':
            data += buffer
            buffer = recv_data(sock)

        # Print the hash
        print(data.decode('utf-8') + f' File Name: {file_name.split("/")[-1]}')


def send_hash(sock, hash_type):
    """
    send_hash is a wrapper to send and handle if the server doesn't support the
        hashing algorithm asked to use
    :param sock: the socket that is connected to the server
    :param hash_type: The type of hashing the client is requesting the server
        to do
    :return: None
    """
    # Send the hash
    send_data(sock, hash_type.encode())
    # Get the server response
    data = recv_data(sock)

    # Handle if the hash isn't supported
    # If it doesn't send 0x1 back it isn't supported
    if data != b'0x1':
        # This is a list of supported hashes by the server
        hash_type = hash_type.strip(b'\0')
        print(f'Server: ERROR!!\n'
              f'Server: The hash algorithm provided, {hash_type}, isn\'t '
              f'supported.\n'
              f'Server: Please select one from the following list '
              f'{data.decode()} and try again\n')
        sock.detach()
        sock.close()
        sys.exit()


def send_data(sock, data):
    """
    This sends data to the server. Only in the specified CHUNK_SIZE and handles
        exceptions
    :param sock: The socket that is connected to the server
    :param data: The byte array to send to the server, broken up into chunks
    :return: None
    """
    try:
        # Send the data
        sock.sendall(data.ljust(CHUNK_SIZE, b'\0'))
    except BrokenPipeError:
        sock.detach()
        sock.close()
        print('Client: Connection broken shutting down')
        sys.exit()
    except TimeoutError:
        sock.detach()
        sock.close()
        print('Client: We have timed out as there was no response from the'
              ' server. Closing connection to the server')
        sys.exit()
    except socket.error as error:
        sock.detach()
        sock.close()
        raise socket.error from error


def recv_data(sock):
    """
    Receives data from the server in CHUNK_SIZE and handles the exceptions
    :param sock: The socket that is connected to the server
    :return: A byte array of data to sent by the server.
    """
    try:
        # Get the data
        return sock.recv(CHUNK_SIZE).strip(b'\0')
    except BrokenPipeError:
        sock.detach()
        sock.close()
        print('Client: Connection broken shutting down')
        sys.exit()
    except TimeoutError:
        sock.detach()
        sock.close()
        print('Client: We have timed out as there was no response from the'
              ' server. Closing connection to the server')
        sys.exit()
    except socket.error as error:
        sock.detach()
        sock.close()
        raise socket.error from error


def main(arguments):
    """
    This is the main function that calls everything else
    :param arguments: Args passed in by the user on the command line
    :return: None
    """

    arg_check(arguments)

    # connect to the server
    sock = connect((arguments.IP_Address, arguments.port))
    # send the hash type
    send_hash(sock, arguments.Hash_Name)
    # prep and send the files
    prep_data(sock, arguments.files)

    # Everything is done wrap it up
    print(f'Client: Closing connection to server on {arguments.IP_Address}')
    sock.close()
    print('Client: Connection closed, exiting session')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This is the client to connect'
                                                 ' to a hashing server')
    parser.add_argument('IP_Address',
                        help='The Server\'s IP Address to connect to',
                        type=str)
    parser.add_argument('Hash_Name',
                        help='The name of the hashing algorithm',
                        type=str)
    parser.add_argument('-p', '--port',
                        help='The Server\'s Port. Default is set to 2345',
                        type=int,
                        default=2345)
    parser.add_argument('files',
                        nargs='*',
                        help='The file(s) to hash',
                        type=str)

    args = parser.parse_args()

    main(args)
