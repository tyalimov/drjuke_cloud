from pyftpdlib.handlers    import FTPHandler
from pyftpdlib.servers     import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

import os

def main():
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(os.getcwd(), perm='elradfmwMT')
    authorizer.add_user(username='test', password='test', perm='elradfmwMT', homedir='resources')
    address = ("127.0.0.1", 21)             
    handler = FTPHandler
    handler.authorizer = authorizer
    server  = FTPServer(address, handler)
    server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except:
        pass
