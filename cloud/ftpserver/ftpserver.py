from pyftpdlib.handlers    import FTPHandler
from pyftpdlib.servers     import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

import os

def main():
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(os.getcwd(), perm='elradfmwMT')
    authorizer.add_user(username='uploader', password='uploader', perm='elradfmwMT', homedir='ftp_data\\malware')
    authorizer.add_user(username='updater', password='updater', perm='elradfmwMT', homedir='ftp_data\\av_distributive')
    address = ("0.0.0.0", 21)             
    handler = FTPHandler
    handler.authorizer = authorizer
    server  = FTPServer(address, handler)
    server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except:
        pass
