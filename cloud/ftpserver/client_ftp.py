import ftplib

def main():
    ftp = ftplib.FTP(host='127.0.0.1', user="test", passwd="test")
    ftp.login()
    ftp.cwd('/resources')
    ftp.dir()
    ftp.quit


if __name__ == '__main__':
    main()