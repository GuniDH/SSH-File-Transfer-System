import struct
from Constants import Other

class Request: # Retrieves request from client

    def __init__(self,client,conn):
        self.conn=conn
        self.client=client

    def unpack_header(self):
        header = self.conn.recv(Other.REQUEST_HEADER_SIZE)
        if not header:
            raise ConnectionAbortedError # Connection with client has been disconnected
        client_id, version, code, payload_size = struct.unpack(f'<{Other.UUID_SIZE}sBHI', header) # < is for little endian following the protocol
        self.payload_size = payload_size
        if version != Other.VERSION:
            raise Exception(f"Version of all clients must be {Other.VERSION}")
        self.client.set_client_id(client_id)
        return client_id,code
        

    def unpack_payload(self):
        return self.conn.recv(self.payload_size)
    