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

## Key Exchange Process  

1. The **client** generates an asymmetric key pair using **RSA**.  
2. The **client** sends its **public key** to the **server**.  
3. The **server** encrypts a newly generated **AES symmetric key** using the **client's public key**.  
4. The **server** sends the encrypted **AES key** back to the **client**.  
5. The **client** decrypts the AES key using its **private RSA key**.  
6. From this point onward, all communication is encrypted and decrypted using **AES**, which both the client and server now share.  

---

## Why Use Both Asymmetric and Symmetric Encryption?  

Asymmetric encryption (RSA) is significantly slower than symmetric encryption algorithms like AES. Additionally, RSA requires much longer key sizes to achieve the same level of security as AES.  

For example, in this project, we use a **256-bit AES key** and a **1024-bit RSA key** to ensure secure communication.  

To securely transmit the AES key without exposing it to attackers, we use **asymmetric encryption** (RSA) for the key exchange. The **public RSA key** is used for encryption, while the **private RSA key**—stored securely on the client side—is used for decryption.  

Once the AES key has been exchanged, all further communication is encrypted using **AES**, which is much more efficient for large amounts of data.  


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

### Author
**Guni**
