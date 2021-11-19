import multiprocessing
import argparse

from client import main


def multi_client(arguments):
    """
    Starts up multiple clients in separate processes
    :param arguments: Args passed in by the user on the command line
    :return: None
    """

    jobs = []
    for i in range(10):
        # Starts up the clients
        process = multiprocessing.Process(target=main(arguments))
        jobs.append(process)
        process.start()


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
    multi_client(args)
