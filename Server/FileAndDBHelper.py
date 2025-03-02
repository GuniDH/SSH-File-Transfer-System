from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random
from MyExceptions import *
from Response import *
import sqlite3
from Constants import Other

# Retrieves port from port file
def get_port():
    try:
        with open('port.info', 'r') as f:
            try:
                port = int(f.read().strip())
                if Other.MAX_PORT >= port >= 0:
                    return port
                print(f'Port should be an integer between 0 to {Other.MAX_PORT}. Using default port {Other.DEFAULT_PORT}.')
                return Other.DEFAULT_PORT
            except ValueError:
                print(f'Port file content should be a port number. Using default port {Other.DEFAULT_PORT}.')
                return Other.DEFAULT_PORT
    except Exception:
        print(f'Error opening port file. Using default port {Other.DEFAULT_PORT}')
        return Other.DEFAULT_PORT

# Creates the clients DB
def clients_db():
    clients_db_conn = sqlite3.connect('clients.db')
    clients_db_conn.text_factory = bytes
    clients_db_conn.cursor().execute('''CREATE TABLE IF NOT EXISTS ClientsTable(ID BLOB CHECK(length(ID) = 16) NOT NULL PRIMARY KEY, 
                                    Name VARCHAR(255), PublicKey BLOB CHECK(length(PublicKey) = 160), LastSeen DATETIME, AES BLOB CHECK(length(AES) = 32))''')
    clients_db_conn.commit()
    return clients_db_conn

# Creates the files DB
def files_db():
    files_db_conn = sqlite3.connect('files.db')
    files_db_conn.text_factory = bytes
    files_db_conn.cursor().execute('''CREATE TABLE IF NOT EXISTS FilesTable(ID BLOB CHECK(length(ID) = 16) NOT NULL, 
                                    "File Name" VARCHAR(255) NOT NULL, "Path Name" VARCHAR(255), Verified INTEGER, PRIMARY KEY(ID,"File Name"))''')
    files_db_conn.commit()
    return files_db_conn

# Generates AES symmetric key, sends it to client and stores in DB
def send_and_update_aes(clients_db_conn, client_id, code, conn, public_key=None):
    cursor = clients_db_conn.cursor()
    if not public_key:
        cursor.execute('''SELECT PublicKey FROM ClientsTable WHERE ID = ?''', (client_id,))
        public_key = cursor.fetchone()[0]
    aes = Crypto.Random.get_random_bytes(32)
    try:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_aes = cipher_rsa.encrypt(aes)
        AESResponse(client_id, encrypted_aes, code).send(conn)
        print(f"Generated AES for client with id {client_id.hex()}: {aes.hex()}")
    except Exception:
        print(f"Public key of client with id {client_id.hex()} is corrupted")
        raise

    cursor.execute('''UPDATE ClientsTable SET AES = ?, PublicKey = ? WHERE ID = ?''', (aes, public_key, client_id))
    clients_db_conn.commit()

# Validates that a client signing up doesn't exist in DB
def validate_client(clients_cursor, name):
    clients_cursor.execute('''SELECT ID FROM ClientsTable WHERE Name = ?''', (name,))
    client_id = clients_cursor.fetchone()
    if client_id:  
        raise DuplicateClientError(f'Client with id {client_id[0].hex()} already registered')

# Validates that an existing client provides correct name according to id in DB
def validate_name_and_id(clients_cursor, client_id, name):
    clients_cursor.execute('''SELECT Name FROM ClientsTable WHERE ID = ?''', (client_id,))
    try:
        real_name = clients_cursor.fetchone()[0].decode('utf-8')
        if real_name != name:
            raise Exception(f"Client with id {client_id.hex()} provided wrong name")
    except Exception:
        raise UnregisteredClientError(f"Client with id {client_id.hex()} does not exist")

# Inserts client to DB
def insert_client(clients_db_conn, client):
    clients_db_conn.cursor().execute('''INSERT INTO ClientsTable (ID, Name, LastSeen) VALUES (?, ?, CURRENT_TIMESTAMP)''',
                                      (client.get_client_id(), client.get_name()))
    clients_db_conn.commit()

# Checks if a file for client exists in DB
def file_exists(files_cursor, client_id, file_name):
    files_cursor.execute('''SELECT 1 FROM FilesTable WHERE ID = ? AND "File Name" = ?''', (client_id, file_name))
    return files_cursor.fetchone()

# Inserts file of client to DB
def insert_file(files_db_conn, client):
    files_db_conn.cursor().execute('''INSERT INTO FilesTable (ID, "File Name", "Path Name", Verified) VALUES (?, ?, ?, 0)''',
                                    (client.get_client_id(), client.get_file_name(), client.get_file_path()))
    files_db_conn.commit()

# Verify file of client - # 1 means verified, 0 means not verified
def verify_file(files_db_conn, client):
    files_db_conn.cursor().execute('''UPDATE FilesTable SET Verified = ? WHERE ID = ? AND "File Name" = ?''', 
                                    (1, client.get_client_id(), client.get_file_name(),))
    files_db_conn.commit()

# Remove file of client (in case of invalid crc)
def remove_file(files_db_conn, client):
    files_db_conn.cursor().execute('''DELETE FROM FilesTable WHERE ID = ? AND "File Name" = ?''', (client.get_client_id(), client.get_file_name(),))
    files_db_conn.commit()

# Retrieves AES symmetric key and name from DB and sets it to client object
def set_aes_name(clients_cursor, client):
    clients_cursor.execute('''SELECT AES, NAME FROM ClientsTable WHERE ID = ?''', (client.get_client_id(),))
    result = clients_cursor.fetchone()
    if not result:
        raise Exception(f"No such client with id {client.get_client_id().hex()}")
    client.set_aes(result[0])
    client.set_name((result[1].decode('utf-8')).rstrip('\0'))
