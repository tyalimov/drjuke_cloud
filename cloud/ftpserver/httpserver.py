import http.server
import socketserver
import urllib
import utils

PORT = 9999
HOST_ADDRESS = "127.0.0.1"
HOST_PORT = 9999

class RequestHandler(http.server.BaseHTTPRequestHandler):
    
    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code)
        self.send_header('Server','python3 http.server Development Server')     
        self.send_header('Date', self.date_time_string())
        self.end_headers()  
    
    def do_GET(self):
        # response for a GET request
        self.send_response(200)
        self.wfile.write(utils.GetHashes())
        
    def do_POST(self):
        self.send_response(404) 
  
def run(server_class = http.server.HTTPServer, handler_class = http.server.BaseHTTPRequestHandler):
    server_address = (HOST_ADDRESS, HOST_PORT)
    httpd          = server_class(server_address, handler_class)
    httpd.serve_forever()

def main():
    run(handler_class = RequestHandler)

if __name__ == '__main__':
    try:
        main()
    except:
        pass