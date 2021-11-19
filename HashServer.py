"""
Author: Joshua McFadden
Description:
This is a python file full of classes that are required by server.py. These can
    be used to recreate my server in a different file or area
"""
import socketserver
import ssl

from hashlib import sha1, sha256, sha512, md5

# Accepted Hash Types
HASH_TYPES = ['sha1', 'sha256', 'sha512', 'md5']
# Chunk size
CHUNK_SIZE = 1024


class SSLHashTCPServer(socketserver.ThreadingTCPServer):
    """
    SSLHashTCPServer is a class adding SSL capabilities to the
    ThreadingTCPServer
    """
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 bind_and_activate=True):
        """
        This defines the server type
        :param server_address: A tuple of (IP Address, Port) to run the server
            on
        :param RequestHandlerClass: Default requirement from socketserver
        :param certfile: The name of the certificate file to use
        :param keyfile: The name of the key file to use
        :param bind_and_activate: Default requirement from socketserver
        """
        socketserver.ThreadingTCPServer.__init__(self, server_address,
                                                 RequestHandlerClass,
                                                 bind_and_activate)

        # Add ssl context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        # Change the socket to use an SSL socket
        self.socket = ssl_context.wrap_socket(self.socket, server_side=True,
                                              do_handshake_on_connect=True)


class HashServerHandler(socketserver.BaseRequestHandler):
    """
    This is my custom Hash Server Handler. Once a request comes in this function
        will process the request
    """
    def handle(self):
        """
        Handles a request made to the server
        :return: None
        """

        try:
            # Receive the hash type requested by the client
            hash_type = self.request.recv(4096).strip(b'\0')
        except BrokenPipeError:
            return  # Close connection and exit

        # Check to see if the hash is supported
        if hash_type.decode('utf-8') not in HASH_TYPES:
            # Send the supported list
            try:
                # Send the supported hash list
                msg = str(HASH_TYPES).encode()
            except TypeError as error:
                raise TypeError('The hash list couldn\'t be converted to a'
                                ' string') from error
            try:
                self.request.sendall(msg.ljust(CHUNK_SIZE, b'\0'))
            except BrokenPipeError:
                return  # Close connection and exit
            return  # Wrong type of hash. Close connection and exit

        try:
            # Hash is supported by the server, let the client know
            self.request.sendall(b'0x1'.ljust(CHUNK_SIZE, b'\0'))
        except BrokenPipeError:
            return  # Close connection and exit

        # Set the hash type
        hash_sum = None
        if hash_type == b'sha1':
            hash_sum = sha1()
        elif hash_type == b'sha256':
            hash_sum = sha256()
        elif hash_type == b'sha512':
            hash_sum = sha512()
        elif hash_type == b'md5':
            hash_sum = md5()

        try:
            # Get how many files are incoming
            num_files = int(self.request.recv(CHUNK_SIZE).strip(b'\0'))
        except BrokenPipeError:
            return  # Close connection and exit
        except TypeError as error:
            raise TypeError('Data received by the client couldn\'t be '
                            'converted to a string') from error

        # Loop through the list of files
        for i in range(num_files):
            try:
                # Get the first file content chunk
                file_content = self.request.recv(CHUNK_SIZE).strip(b'\0')
            except BrokenPipeError:
                return  # Close connection and exit
            while file_content != b'':
                # Update the hash
                hash_sum.update(file_content)
                try:
                    # Continue to get the file content chunks and loop
                    file_content = self.request.recv(CHUNK_SIZE).strip(b'\0')
                except BrokenPipeError:
                    return  # Close connection and exit

            # Add the formatted msg to return to the user to the string
            location = 0
            sending = f'Server: Hash: {hash_sum.hexdigest()}'.encode()
            while True:
                if len(sending) > (CHUNK_SIZE + location):
                    try:
                        # Still more data to send but send this chunk over
                        self.request.sendall(sending[location:
                                                     (CHUNK_SIZE + location)])
                    except BrokenPipeError:
                        return  # Close connection and exit
                    location += CHUNK_SIZE
                else:
                    try:
                        # This is all the data send it once and then send \0 to
                        # tell the client no more data is to be sent in the loop
                        self.request.sendall(sending[location:]
                                             .ljust(CHUNK_SIZE, b'\0'))
                        self.request.send(b'\0'.ljust(CHUNK_SIZE, b'\0'))
                    except BrokenPipeError:
                        return  # Close connection and exit
                    break

        # Close connection and exit
        return
