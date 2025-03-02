import socket
import struct
import uuid
import os
import cksum
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Client import *
from Request import *
from FileAndDBHelper import *
from Constants import *


class Server:  # Represents a server hosting multiple clients by generating a thread for each of them

    def __init__(self):
        self.file_lock, self.db_lock = threading.Lock(), threading.Lock()

    def handle_client(self, conn, addr):
        print(f'Connected by {addr}')
        client = Client()
        clients_db_conn = clients_db()  # Each thread should open its own database connection
        files_db_conn = files_db()
        start_time, packet_counter = time.time(), 0  # For tracking file sending time

        while True:
            try:
                request = Request(client, conn)
                client_id, code = request.unpack_header()
                payload = request.unpack_payload()
                match code:
                    case RequestCodes.REGISTRATION:
                        # Client registration (requires locking database)
                        client.set_name(payload.rstrip(b'\0').decode('utf-8'))
                        with self.db_lock:
                            validate_client(clients_db_conn.cursor(), client.get_name())  # Make sure client didn't already register       
                            client.set_client_id(uuid.uuid4().bytes)
                            SuccessfulRegistrationResponse(client.get_client_id()).send(conn)
                            insert_client(clients_db_conn, client)
                        print(f"Client with id {client.get_client_id().hex()} has signed up")

                    case RequestCodes.PUBLIC_KEY:
                        # Public key exchange (requires locking database)
                        client.set_name(payload[:Other.NAME_SIZE].rstrip(b'\0').decode('utf-8'))
                        with self.db_lock:
                            validate_name_and_id(clients_db_conn.cursor(), client.get_client_id(),
                                                 client.get_name())  # Make sure client is registered in DB and that the name client provided is fitting the name in DB
                            public_key = payload[Other.NAME_SIZE:]  # Make sure client is registered in DB and that the name client provided is fitting the name in DB         
                            send_and_update_aes(clients_db_conn, client.get_client_id(),
                                                ResponseCodes.RECEIVED_PUBKEY_SENDING_AES, conn, public_key)
                            # Generate AES symmetric key, sends it to client and stores in DB
                            print(f"Client with id {client.get_client_id().hex()} has sent public key: {public_key.hex()}")
                                
                    case RequestCodes.RECONNECTION:
                        # AES key resend (requires locking database)
                        client.set_name(payload.rstrip(b'\0').decode('utf-8'))
                        with self.db_lock:
                            validate_name_and_id(clients_db_conn.cursor(), client.get_client_id(),
                                                 client.get_name())  # Make sure client is registered in DB and that the name client provided is fitting the name in DB
                            send_and_update_aes(clients_db_conn, client.get_client_id(),
                                                ResponseCodes.RECONNECTION_SUCCEEDED_SENDING_AES, conn)
                            # Generate AES symmetric key, sends it to client and stores in DB
                        print(f"Client with id {client.get_client_id().hex()} has logged in")

                    case RequestCodes.SENDING_FILE:
                        # File transfer (requires locking both file I/O and database)
                        offset = Other.CONTENTSIZE_SIZE + Other.FILE_NAME_SIZE + Other.ORIG_FILE_SIZE + Other.PACKET_NUM_TOTAL_PACKETS_SIZE
                        content_size, orig_file_size, total_packets, packet_num, file_name = struct.unpack(
                            f'<IIHH{Other.FILE_NAME_SIZE}s', payload[:offset])

                        # Locking database access
                        with self.db_lock:
                            if packet_num == 1:
                                set_aes_name(clients_db_conn.cursor(), client)  # Retrieve AES and name to client from DB (name for file path, aes for decrypting file)
                                client.set_file_name(os.path.basename(
                                    file_name.rstrip(b'\0').decode('utf-8')))  # Basename removes characters such as ../ to prevent directory traversal attack
                                if file_exists(files_db_conn.cursor(), client.get_client_id(), 
                                               client.get_file_name()):  # Check that a client's file doesn't already exist in DB 
                                                                         # (the protocol didn't mention but I chose to not allow overwriting existing files)  
                                    raise DuplicateFileError(f'File {client.get_file_name()} for client with id {client.get_client_id().hex()} already exists') 
                                client.set_file_path(os.path.join('client_files', client.get_name() + '_files', client.get_file_name()))
                                insert_file(files_db_conn, client)  # Insert client's file to DB

                        # Locking file access
                        with self.file_lock:

                            if packet_num == 1:
                                os.makedirs(os.path.join('client_files', client.get_name() + '_files'),
                                            exist_ok=True)  # Make directory for client's files
                                client.open_file('wb')  # Open file to write to it and copy client's file

                            offset = Other.CONTENTSIZE_SIZE + Other.FILE_NAME_SIZE + Other.ORIG_FILE_SIZE + Other.PACKET_NUM_TOTAL_PACKETS_SIZE
                            encrypted_content = payload[offset:]
                            packet_counter += 1
                            if packet_counter != packet_num:
                                raise Exception(f"Packets sent in wrong order from client with id {client.get_client_id().hex()}")
                            client.write_to_file(encrypted_content)
                            print(f"Received packet number {packet_num} for file {client.get_file_name()} from client with id {client.get_client_id().hex()}")
                            ReceivedMessageResponse(client.get_client_id()).send(conn)  # To indicate there was no problem receiving the packet

                            if packet_num == total_packets:  # After writing all encrypted packets, re-read the whole encryped file and decrypt it
                                client.close_file()
                                client.open_file('rb')
                                encrypted_file = client.read_from_file()
                                if len(encrypted_file) != content_size:
                                    raise Exception(f"Invalid content size from client with id {client.get_client_id().hex()}")
                                cipher = AES.new(client.get_aes(), AES.MODE_CBC, iv=bytes(Other.IV_SIZE))
                                decrypted_file = Padding.unpad(cipher.decrypt(encrypted_file), AES.block_size)  # Decrypt all file                   
                                if len(decrypted_file) != orig_file_size:
                                    raise Exception(f"Invalid original size from client with id {client.get_client_id().hex()}")
                                client.close_file()
                                client.open_file('wb')
                                client.write_to_file(decrypted_file)  # Re-writing the decrypted verison of file
                                client.close_file()
                                crc = cksum.memcrc(decrypted_file)  # Calculating cksum
                                FileReceivedResponse(client.get_client_id(), content_size,
                                                     client.get_file_name().encode('utf-8'), crc).send(conn)

                    case RequestCodes.VALID_CRC:
                        # File verification (requires locking database)
                        client.set_file_name(payload.rstrip(b'\0').decode('utf-8'))
                        if not file_exists(files_db_conn.cursor(), client.get_client_id(), client.get_file_name()):
                            raise InexistentFileError(
                                f'File {client.get_file_name()} does not exist in DB. Therefore there is no file to verify.')
                        with self.db_lock:  # Verifying file after receiving valid crc
                            verify_file(files_db_conn, client)
                        ReceivedMessageResponse(client.get_client_id()).send(conn)
                        end_time = time.time()
                        print(f'Successfully received file {client.get_file_name()} from client {client.get_client_id().hex()} in {end_time - start_time} seconds')
                        conn.close()
                        clients_db_conn.close()
                        files_db_conn.close()
                        break  # Taking care of client finished because file received successfully

                    case RequestCodes.INVALID_CRC_RESENDING | RequestCodes.INVALID_CRC_ABORT:
                        client.set_file_name(payload.rstrip(b'\0').decode('utf-8'))
                        if not file_exists(files_db_conn.cursor(), client.get_client_id(), client.get_file_name()):
                            raise InexistentFileError(
                                f'File {client.get_file_name()} does not exist in DB. Therefore there is no file to attempt sending again or abort.')
                        with self.db_lock:  # Removing file from DB in order to be able re-adding it during the next attempt, or removing it to abort after 4 attempts
                            remove_file(files_db_conn,
                                        client)  # The protocol did not mention a response to send in the case of resending
                        with self.file_lock:  # Removing file from file system as well
                            os.remove(os.path.join('client_files', client.get_name() + '_files', os.path.basename(
                                client.get_file_name())))  # Basename removes characters such as ../ to prevent directory traversal attack
                        if code == RequestCodes.INVALID_CRC_ABORT:
                            ReceivedMessageResponse(client.get_client_id()).send(
                                conn)  # In this case of abort sending this response following the protocol
                            print(f'Abort. Cannot receive file {file_name} from client {client_id.hex()}')
                            conn.close()
                            clients_db_conn.close()
                            files_db_conn.close()
                            break  # Taking care of client finished because file cannot be sent after 4 attempts
                        
            except UnregisteredClientError as e:
                print(f"Client has to sign up exception: {e}")
                FailedReconnectionResponse(client.get_client_id()).send(conn)
            except DuplicateClientError as e:
                print(f"Client already signed up exception: {e}")
                FailedRegistrationResponse().send(conn)
            except (DuplicateFileError,
                    InexistentFileError) as e:  # By the protocol, there are no specific responses for these errors so general failure will be sent
                print(f"Exception: {e}")
                GeneralFailureResponse().send(conn)
            except (OSError, # Will usually occur after 4 attempts that client sends request after getting error code 1607 from server (following the protocol)
                    ConnectionAbortedError) as e:  
                if e.errno == Other.CONNECTION_ABORTED_ERROR:
                    print(f"Connection with client has been aborted: {e}")  # In this case there no connection therefore no response to client
                conn.close()
                clients_db_conn.close()
                files_db_conn.close()
                break
            except Exception as e:
                print(f"Exception: {e}")
                GeneralFailureResponse().send(conn)

    """

    Runs the server with a TCP socket to accept incoming client connections.
    When a client connects, it submits the handling of that client to a thread pool.
    I chose using a thread pool over creating a new thread for each client connection because:

    1. Creating a new thread for each client can lead to high memory and resource usage.
    A thread pool limits the number of threads working simultaneously (here I chose 10), thus preventing the server from overload.

    2. Thread creation and destruction are relatively expensive operations. By reusing threads from the pool,
    the server can handle client requests more efficiently, without creating and destroying threads frequently, thus reducing latency. 

    """
    
    def run(self):
        try:
            host, port = '', get_port()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # IPV4, TCP
                s.bind((host, port))
                s.listen()
                print(f"Server listening on port {port}")
                with ThreadPoolExecutor(max_workers=Other.MAX_WORKERS) as executor:  # Use thread pool executor (max workers is the maximum amount of clients running simultaneously)
                    while True:
                        conn, addr = s.accept()
                        executor.submit(self.handle_client, conn, addr)  # Submit client handling to the pool

        except Exception as e:
            print(f"Exception: {e}")
    