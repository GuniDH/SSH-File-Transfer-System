# Secure File Transfer System by Guni #

## Overview

This project implements a secure **client-server file transfer system** using a combination of **RSA and AES encryption**. It ensures that files transferred between the client and server remain confidential and protected from unauthorized access.

## Features

- **Hybrid Encryption**: Uses **AES (Advanced Encryption Standard)** for symmetric encryption and **RSA** for asymmetric key exchange.
- **Data Integrity Verification**: Implements CRC to ensure the integrity of transferred files and detect transmission errors.
- **Backup utilization**: Sqlite database

## Technologies Used

I developed server using VSC with python 3.12.1, and developed client using VS with C++17. Socket programming in client was done using Boost, and in server using Socket module. Encryption is done in client using Crypto++, and in server using Pycryptodome module.
Database was written by Sqlite.

## Key exchange

• The client generates a pair of assymetric keys: RSA keys (also known as Diffie-Hellman).
• The client sends the public key to the server.
• The server uses it to encrypt the symetric key: the AES key.
• The encrypted AES key is sent back to the client and can be decrypted using the client's private key.
• From that time and on, all the encrypted information will be encrpyted and decrypted with the AES key, which both the client and the server possess.

## Why use both symmetric and asymmetric keys?
Asymmetric key's encryption and decryption operations are significantly slower compared to symmetric encryption algorithms like AES.
RSA requires longer key sizes to achieve comparable security levels to symmetric encryption algorithms. For example, in this project we used a 256-bit AES key and 1024-bit RSA key.
To pass the symmetric key successsfully to the client without an attacker reading it, we need to use a pair of asymmetric keys. The public key is only for encryption, and the private key is for decryption. Every one can have the public key, but the private key is stored (hopefully) safely, client-side.

## Notes:
• I chose the packet size for file transfer to be 8KB in order to enable faster transfer of larger files. I performed grid-search to find the optimal size for this project,
considering the fact the limited amount for packets to be sent is 2^16-1 due to the size of total packets field in the header.

• File overwriting is not allowed thus if the ame client
provides the system with an existing file path a general error (1607) will be returned.

• I work with ThreadPool to support multiple clients.
I chose this method over creating a new thread for each client connection because:

1. Creating a new thread for each client can lead to high memory and resource usage.
 A thread pool limits the number of threads working simultaneously (here I chose 10), thus preventing the server from overload.

2. Thread creation and destruction are relatively expensive operations. By reusing threads from the pool, the server can
 handle client requests more efficiently, without creating and destroying threads frequently, thus reducing latency. 

• I used os.path.basename to ignore signs such as ../ in file names,
and thus prevent Directory Traversal Attack.
Detailed vulnerabilities analysis is provided in the docx file.


## License

This project is licensed under the **MIT License**.

---

### Author

**Guni**
