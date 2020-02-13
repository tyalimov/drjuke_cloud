import http.server
import socketserver
import urllib
import utils

PORT = 9999
HOST_ADDRESS = "0.0.0.0"
HOST_PORT = 9999

class RequestHandler(http.server.BaseHTTPRequestHandler):
    
    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code)
        self.send_header('Server','python3 http.server Development Server')     
        self.send_header('Date', self.date_time_string())
        self.end_headers()  
    
    def do_GET(self):
        # response for a GET reques
        self.send_response(200)
        self.wfile.write(utils.GetHashes())
        
    def do_POST(self):
        print("Got post")
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        filename = post_data.decode('utf-8')
        self.send_response(200)
        self.wfile.write(utils.AiScan(filename).encode('utf-8'))
  
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