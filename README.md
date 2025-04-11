# SSH Secure File Transfer System by Guni #

## Overview

This project implements SSH protocol for a secure **client-server file transfer system** using a combination of **RSA and AES encryption**. It ensures that files transferred between the client and server remain confidential and protected from unauthorized access. 

## Features

- **Hybrid SSH Encryption**: Uses **AES (Advanced Encryption Standard)** for symmetric encryption and **RSA** for asymmetric key exchange.
- **Data Integrity Verification**: Implements CRC to ensure the integrity of transferred files and detect transmission errors.
- **Backup utilization**: Sqlite database

## SSH Protocol 

2 Cases which are differentiable by the existence of files in the client's PC:

a. New client:
1. The client sends a registration request
2. The server sends the client its unique uuid
3. The client generates an asymmetric key pair using **RSA** and sends the public key to the server
4. The server encrypts a newly generated **AES symmetric key** using the **client's public key**
5. The server sends the encrypted **AES key** to the client  
6. The client decrypts the AES key using its **private RSA key**
7. From this point onward, all communication is encrypted and decrypted using **AES**, which both the client and server now share
8. The client slices the file into packets of 8KB, encrypts each packet with the **AES** symmetric key then sends them to the server
9. CRC ensures the integrity of the transferred file and resends the file again if needed, up to 3 more attempts

b. Existing client:
1. The client sends a reconnection request with its previously generated uuid
2. The server accepts if the client exists
3. The client generates an asymmetric key pair using **RSA** and sends the public key to the server
4. The server encrypts the previously generated **AES symmetric key** that was retrieved from the database, using the **client's public key**
5. The server sends the encrypted **AES key** to the client  
6. The client decrypts the AES key using its **private RSA key**
7. From this point onward, all communication is encrypted and decrypted using **AES**, which both the client and server now share
8. The client slices the file into packets of 8KB, encrypts each packet with the **AES** symmetric key then sends them to the server
9. CRC ensures the integrity of the transferred file and resends the file again if needed, up to 3 more attempts

****
---

## Notes:

• File overwriting is not allowed thus if the same client
provides the system with an existing file path a general error (1607) will be returned.

• I work with ThreadPool to support multiple clients.
I chose this method over creating a new thread for each client connection because:

1. Creating a new thread for each client can lead to high memory and resource usage.
 A thread pool limits the number of threads working simultaneously (here I chose 10), thus preventing the server from overload.

2. Thread creation and destruction are relatively expensive operations. By reusing threads from the pool, the server can
 handle client requests more efficiently, without creating and destroying threads frequently, thus reducing latency. 

### Author
**Guni**
