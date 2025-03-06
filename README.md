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
