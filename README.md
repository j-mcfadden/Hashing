# Hash Server & Client
Author: Joshua McFadden

## Overview
- [Server](#server)
- [Client](#client)

## Server
### Synopsis
```bash
python3 server.py -e|-l
python3 server.py -p [PORT] -e|-l
```

### Description
**Server.py** is a threaded TCP server for cryptographically hashing files. The
server waits for a client connection on a designated *IP Address* on a designed
*Port*. After the connection has been made the client sends the hashing method
over to the server, it checks it against its supported hashing types and either
confirms or denies the request. After confirmation the client tells the server
how many files it will be hashing, then the server starts receiving the data in
chunks. Once the hash has been completed it sends the data to the client and
starts on the next file. Once all files have been completed the server closes
the connection to the client.

### Optional Argument
- **-p/--port**: It will tell the server what port to expose. Defaults to
2345
#### Mutually Exclusive Argument, Required
- **-e/--external**: Uses the DHCP address assigned to the primary 
  ethernet port for the server's address
- **-l/--local**: Uses LocalHome for the server's address

## Client
### Synopsis
```bash
python3 client.py [IP Address] [Hash Name] FILE(S)...
python3 client.py [IP Address] -p [PORT] [Hash Name] FILE(S)...
```
### Description
**Client.py** is a network client for cryptographically hashing files. The client
connects to a server listening on a network at an *IP Address* on a designated
*Port*. After connecting the client sends the *Hash Name* to the server to see
if it is supported. Once confirmed the client sends the *file(s)* contents over
the network to the server. The client will then display the hash to the user.

### Required Arguments
- **IP_Address**: The Server's IP Address to connect to
- **Hash_Name**: The name of the hashing algorithm
- **files**: The file(s) to hash. A list of files that has a minimum of 1
### Optional Argument
- **-p/--port**: It will tell the client what port to use. Defaults to 2345
