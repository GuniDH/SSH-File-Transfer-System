from abc import ABC
import struct
from Constants import ResponseCodes,Other

class Response(ABC): # Creates response for client
    def pack_header(self,code: int, payload_size: int):
        self.header = struct.pack('<BHI', Other.VERSION, code, payload_size) # < is for little endian following the protocol

    def send(self, conn):
        try:
            conn.sendall(self.header)
            conn.sendall(self.payload)
        except: # Exception will be printed in the try-except block of handle_client function
            pass

class SuccessfulRegistrationResponse(Response):
    def __init__(self, client_id:bytes):
        self.pack_header(ResponseCodes.REGISTRATION_SUCCEEDED,Other.UUID_SIZE)
        self.pack_payload(client_id)

    def pack_payload(self, client_id:bytes):
        self.payload = struct.pack(f'{Other.UUID_SIZE}s',client_id)

class FailedRegistrationResponse(Response):
    def __init__(self):
        self.pack_header(ResponseCodes.REGISTRATION_FAILED,0)
        self.pack_payload()

    def pack_payload(self):
        self.payload = struct.pack('0s',b"")

# For public key and reconnection client requests (response codes are either 1602 or 1605)
class AESResponse(Response):
    def __init__(self, client_id:bytes, encrypted_aes:bytes, code:int):
        self.pack_payload(client_id,encrypted_aes,code)

    def pack_payload(self, client_id:bytes, encrypted_aes:bytes,code:int):
        self.pack_header(code,Other.UUID_SIZE+len(encrypted_aes))
        self.payload = struct.pack(f'{Other.UUID_SIZE}s{len(encrypted_aes)}s', client_id, encrypted_aes)

class FileReceivedResponse(Response):
    def __init__(self, client_id:bytes, content_size:int, file_name:bytes, cksum:int):
        offset = Other.UUID_SIZE+Other.CONTENTSIZE_SIZE+Other.FILE_NAME_SIZE+Other.CKSUM_SIZE
        self.pack_header(ResponseCodes.VALID_CRC,offset)
        self.pack_payload(client_id,content_size,file_name,cksum)

    def pack_payload(self, client_id:bytes, content_size:int, file_name:bytes, cksum:int):
        self.payload = struct.pack(f'<{Other.UUID_SIZE}sI{Other.FILE_NAME_SIZE}sI', client_id,content_size,file_name,cksum)

class ReceivedMessageResponse(Response):
    def __init__(self, client_id:bytes):
        self.pack_header(ResponseCodes.RECEIVED_MSG,Other.UUID_SIZE)
        self.pack_payload(client_id)

    def pack_payload(self, client_id:bytes):
        self.payload = struct.pack(f'{Other.UUID_SIZE}s',client_id)

class FailedReconnectionResponse(Response):
    def __init__(self, client_id:bytes):
        self.pack_header(ResponseCodes.RECONNECTION_FAILED,Other.UUID_SIZE)
        self.pack_payload(client_id)

    def pack_payload(self,client_id:bytes):
        self.payload = struct.pack(f'{Other.UUID_SIZE}s',client_id)

class GeneralFailureResponse(Response):
    def __init__(self):
        self.pack_header(ResponseCodes.GENERAL_FAILURE,0)
        self.pack_payload()

    def pack_payload(self):
        self.payload = struct.pack('0s',b"")
