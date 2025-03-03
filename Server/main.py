# Server for RSA encrypted file transfer system
# Author: Guni 


from Server import Server


def main():
    
    try:
        server = Server()
        server.run()
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    main()
