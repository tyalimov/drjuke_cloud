from pyftpdlib.handlers  import FTPHandler
from pyftpdlib.servers   import FTPServer

def main():
    address = ("0.0.0.0", 21)               # listen on every IP on my machine on port 21
    server  = FTPServer(address, FTPHandler)
    server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except:
        pass
