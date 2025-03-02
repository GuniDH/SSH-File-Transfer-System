class Client: # Represents a client communicating with the server

    def __init__(self):
        self.__aes = self.__name = self.__client_id = self.__file_path = self.__file_name = self.__file = None

    def set_aes(self, aes):
        self.__aes = aes

    def set_file_path(self, file_path):
        self.__file_path = file_path

    def set_file_name(self, file_name):
        self.__file_name = file_name

    def set_name(self, name):
        self.__name = name

    def set_client_id(self, client_id):
        self.__client_id = client_id

    def get_aes(self):
        return self.__aes

    def get_file_path(self):
        return self.__file_path

    def get_file_name(self):
        return self.__file_name

    def get_name(self):
        return self.__name

    def get_client_id(self):
        return self.__client_id

    def open_file(self,flag):
        self.__file = open(str(self.__file_path),flag)

    def close_file(self):
        if self.__file:
            self.__file.close()
    
    def read_from_file(self):
        if self.__file:
            return self.__file.read()
    
    def write_to_file(self,content):
        if self.__file:
            self.__file.write(content)
