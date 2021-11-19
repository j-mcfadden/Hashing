"""
Author: Joshua McFadden
Description:
    A server to take in files, hash them and return them to the client
"""
import argparse
import socket
import sys
import threading

from HashServer import SSLHashTCPServer, HashServerHandler


def get_ip():
    """
    get_ip will get the local machines IP address of the device if external IP
        is selected by the user
    :return: str IP of device
    """
    try:
        # Make a regular socket to find the computer's IP address
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
    except socket.error:
        print('The socket couldn\'t resolve your devices IP address, make sure'
              'that your network interface is up')
        sys.exit()

    try:
        sock.close()
    except socket.error as error:
        raise socket.error from error

    return ip


def arg_check(arguments):
    """
    arg_check makes sure that the arguments passed in by the user are valid
    :param arguments: Arguments passed in by the command line
    :return: None
    """
    if not ((arguments.port > 0) and (arguments.port < 65535)):
        print(f'The Port entered {arguments.port} is not valid '
              f'please try again')


def build_server(ip, port):
    """
    This creates the server thread, ssl server object and start the thread. It
        will handle shutting it down gracefully as well by the user entering
        Quit or quit. It only looks at the first char
    :param ip: the address of the server to use
    :param port: the port to run the server on
    :return: None
    """
    print('\nServer: Starting')

    # Allow the server to reuse the address
    SSLHashTCPServer.allow_reuse_address = True

    # Create a TCP threading server instance
    server = SSLHashTCPServer((ip, port), HashServerHandler, 'server.crt',
                              'server.key')

    print(f'Server: Running on {ip}:{port}')

    server_thread = threading
    while True:
        try:
            try:
                # Create a thread for the server to run on
                server_thread = threading.Thread(target=server.serve_forever)
            except threading.ThreadError as error:
                server.server_close()
                raise threading.ThreadError('Error creating the threading'
                                            ' server') from error
            try:
                # Start the thread
                server_thread.start()
            except threading.ThreadError as error:
                raise threading.ThreadError('Error starting the threading'
                                            ' server') from error

            # This is used to close the server down
            user = input('Server: Enter quit to exit the server:')
            if user[0] == 'q' or user[0] == 'Q':
                break
            print('Server: Input bad, try again\n')

        except KeyboardInterrupt:
            print('\nServer: Starting to shutting down')
            # Shut down gracefully
            server.shutdown()
            server.server_close()
            # If the keyboard interrupt happened after join it up to close it
            # down
            if server_thread.is_alive():
                server_thread.join()
            print('Server: Finished shut down')
            sys.exit()

    try:
        print('\nServer: Starting to shutting down')
        # Shut down gracefully
        server.shutdown()
        server.server_close()
        server_thread.join()
        print('Server: Finished shut down')
    except KeyboardInterrupt:
        print('\nServer: Starting to shutting down')
        # Shut down gracefully
        server.shutdown()
        server.server_close()
        server_thread.join()
        print('Server: Finished shut down')
        sys.exit()


def main(arguments):
    """
    run the server
    :param arguments: the arguments passed in from the command line
    :return: None
    """
    arg_check(arguments)

    # One of the threads is used to wait to shut down the server
    # Create a server that can be used on the LAN or WAN if ports are forward
    if arguments.external is not None:
        control = threading.Thread(target=build_server(arguments.external,
                                                       arguments.port))
    # Create a server that responds to 127.0.0.1
    else:
        control = threading.Thread(target=build_server(arguments.local,
                                                       arguments.port))

    try:
        control.start()
    except threading.ThreadError as error:
        raise threading.ThreadError('Failed to start the main thread') \
            from error
    control.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port',
                        help='The Server\'s Port to expose. Default is set to'
                             ' 2345',
                        type=int,
                        default=2345)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--external',
                       help='Uses the DHCP address assigned to the primary '
                            'ethernet port for the server\'s address',
                       action='store_const',
                       const=f'{get_ip()}')
    group.add_argument('-l', '--local',
                       help='Uses LocalHome for the server\'s address',
                       action='store_const',
                       const='127.0.0.1')

    args = parser.parse_args()

    main(args)
