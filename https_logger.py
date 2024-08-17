from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import argparse
import datetime
import sys
import csv
import json
import os

start_datetime_str = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

epilog_text = f'''
EXAMPLES:
        {sys.argv[0]} --no-https
        {sys.argv[0]} --key-file /etc/letsencrypt/live/your_dom/privkey.pem --cert-file /etc/letsencrypt/live/your_dom/fullchain.pem
        {sys.argv[0]} --no-https -L https://example.com
        {sys.argv[0]} --no-https -L https://example.com --redirect-code 302
        {sys.argv[0]} --no-https -f ~/scripts/logger.html
        {sys.argv[0]} --no-https -o /tmp/logs.txt --log-format txt
        {sys.argv[0]} --no-https -f ~/scripts/logger.html -L https://example.com --redirect-code 302
ALLOW MULTIPLE FILES TO BE SERVER:
        -f specified with combination of [-if, -w, -id] will be default file to serve if requested path not in allowed files. E.g index.html
        -if and -w can be used together.
        -id specified directory where files should be found. It will be appended to requested path to compare against allowed files.
        Examples:
                # Read allowed files that located in www folder, if requested path not found/allowed www/index.html will be served
                find www -type f > allowed_files
                python {sys.argv[0]} --no-https -o test.json -of json-txt  -f www/index.html -w allowed_files --www www
                # Allow file to be served from current folder.
                python /diskD/tools/pyhttps-server/https_logger.py --no-https -o test.json -of json-txt -if ./test.txt -if ./LICENSE

REDIRECT:
        Read docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections
OUTPUT FORMATS EXAMPLES:
        txt: 
        127.0.0.1;40312;GET /adasdadafhtrewdfs HTTP/1.1
        json-txt:
                "{{"Client IP": "127.0.0.1", "Client Port": 50622, "Request": "GET /sdfsdfdsfsdf HTTP/1.1", "Request Body": "", 
                "Request Headers": "Host: localhost\\nUser-Agent: curl/8.7.1\\nAccept: */*\\n\\n"}}"
                # Get unique Client IPs:
                cat pyhttp.log | jq '.["Client IP"]' | sort -u
                # Filter by IP
                cat pyhttp.log | jq 'select(.["Client IP"] == "10.10.10.10")'
                # Filter by string in headers
                cat pyhttp.log | jq 'select(.["Request Headers"] | contains("curl"))'

DEFAULT HEADERS:
        Content-Length: Updated automatically
        Content-Type:   text/html

SECURITY WARNING:
        User controlled input will be logged to log file without any checks or validation.
        Python HTTP security warning: https://docs.python.org/3/library/http.server.html#security-considerations 
'''
parser = argparse.ArgumentParser(description='Python simple HTTP server for different testing operations.',     
                                 epilog=epilog_text,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
http_group = parser.add_argument_group('HTTP', 'Configure SSL usage and ports')
http_group.add_argument('--no-https', action='store_true', help='Run HTTP, default HTTPs.')
http_group.add_argument('-p', '--port', type=int, help='Port to listen on, default 443 or 80 if --no-https specified.')
http_group.add_argument('--key-file', help='File with private key, required for HTTPs.')
http_group.add_argument('--cert-file', help='File with server certificate, required for HTTPs.')

server_header_group =  parser.add_argument_group('Server Header', 'Configure Server Header, e.g. change Server: "BaseHTTP/0.6 Python/3.11.9"')
server_header_group.add_argument('--server-version', help='Default: Apache/2.4')
server_header_group.add_argument('--sys-version', help='Default: ""')

logging_group = parser.add_argument_group('Logging', 'Configure logging')
logging_group.add_argument('-o', '--log-file', help='Path to file where logs will be saved.',
                           default=f'pyhttp{start_datetime_str}.log')
logging_group.add_argument('-of', '--log-format', help='Format for logging.',
                           choices=['txt', 'json-txt', 'csv'], default='json-txt')
logging_group.add_argument('--url-decode', help='Use urllib to decode Headers and Body from Requests. Default: False',
                           action='store_true')

other_group = parser.add_argument_group('CONTENT CONTROL')
other_group.add_argument('-L', '--redirect', help='URL to redirect user. Can be combined --redirect-code, default https://example.com')
file_option_help = '''Return specified file content in response. It will be default file to serve.
                      Use-case: empty html with meta tag/JS script can be used to redirect user/collect additional info etc.'''
other_group.add_argument('-f', '--content-file', help=file_option_help)
other_group.add_argument('-if', '--include-file', help='Allow to serve this files if allowed.', action='append', default=[])
other_group.add_argument('-w', '--allowed-file', help='Read files allowed to serve from specified ALLOWED-FILE', default='')
other_group.add_argument('-id', '--www', help='Directory where allowed files located', default='.')

other_group.add_argument('--redirect-code', choices=[301, 302, 303, 307, 308], default=301, type=int)
add_header_help = '''Add custom HTTP header to response. 
                     Overwrites other parameters e.g -L https://example.com -H
                     'Location: https://test.com' will results in redirection to https://test.com'''
parser.add_argument('-H', '--add-header', help=add_header_help, action='append', default=[])
args = parser.parse_args()


def get_body(http_handler_instance):
        if (file_path := args.www+http_handler_instance.path.split('?')[0]) in args.allowed_files:
                with open(file_path, 'rb') as f:
                        data = f.read()
                return data
        elif args.content_file:
                with open(args.content_file, 'rb') as f:
                        data = f.read()
                return data
        return b''

def get_request_body(http_handler_instance):
        if http_handler_instance.headers["Content-Length"]:
                content_length = int(http_handler_instance.headers["Content-Length"])
                data = http_handler_instance.rfile.read(content_length)
        else:
                data = b''
        return data

def prepare_log_str(http_handler_instance):
        data = {}
        data.update({'Client IP': http_handler_instance.client_address[0]})
        data.update({'Client Port': http_handler_instance.client_address[1]})
        data.update({'Request': http_handler_instance.requestline})
        data.update({'Request Body': get_request_body(http_handler_instance).decode('utf-8')})
        data.update({'Request Headers': str(http_handler_instance.headers)})

        if args.log_format == 'json-txt':
                return json.dumps(data)
        
        if args.log_format == 'txt':
                return f'{data["Client IP"]};{data["Client Port"]};{data["Request"]}'
        if args.log_format == 'csv':
                return data



def log_into_file(log_str):
        if args.log_format == 'csv':
                write_csv_header = not os.path.isfile(args.log_file)
                with open(args.log_file, 'a+', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=log_str.keys())
                        if write_csv_header:
                                writer.writeheader()
                                write_csv_header = False
                        writer.writerow(log_str)
        else:
                with open(args.log_file, 'a+') as f:
                        f.write(log_str + '\n')

def _parse_arg_header_str(header_str):
        return {header_str.split(':')[0]: ''.join(header_str.split(':')[1:])}

def get_arg_headers_dict():
        res_dict = {}
        for h in args.add_header:
                res_dict.update(_parse_arg_header_str(h))
        return res_dict

def add_custom_headers(hhttp):
        skip_this_headers = ['Location', 'Content-Type']
        for h in args.parsed_headers:
                if h in skip_this_headers:
                        continue
                hhttp.send_header(h, args.parsed_headers[h])

def get_allowed_files():
        if args.allowed_file:
                try:
                        with open(args.allowed_file, encoding='UTF-8') as f:
                                allowed_to_serve = [file.strip() for file in f.readlines()]
                except FileNotFoundError:
                        print(f'File {args.allowed_file} not found !')
                        exit(0)
        else:
                allowed_to_serve = []             
        if args.include_file:
                allowed_to_serve += args.include_file
        return allowed_to_serve


args.parsed_headers = get_arg_headers_dict()
args.allowed_files = get_allowed_files()


class MyHTTPHandler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        server_version = 'Apache/2.4'
        sys_version = ''

        def parse_request(self) -> bool:
                return_data = super().parse_request()
                log_into_file(prepare_log_str(self))
                return return_data

        def do_GET(self):
                content_type_header_value = args.parsed_headers.get('Content-Type', 'text/html')
                if args.redirect:
                        self.send_response(args.redirect_code)
                        self.send_header('Content-Type', content_type_header_value)
                        location_header_value = args.parsed_headers.get('Location', args.redirect)
                        location_header_value = location_header_value if location_header_value else 'https://example.com'
                        self.send_header('Location', location_header_value)
                        self.send_header('Content-Length', 0)
                        add_custom_headers(self)
                        self.end_headers()
                else:
                        body_data = get_body(self)
                        self.send_response(200)
                        self.send_header('Content-Type', content_type_header_value)
                        self.send_header('Content-Length', len(body_data))
                        add_custom_headers(self)
                        self.end_headers()
                        self.wfile.write(body_data)

        def do_POST(self):
                self.do_GET()
        
        def do_HEAD(self):
                self.do_GET()
        
        def do_OPTIONS(self):
                self.do_GET()

                

server_port = 80 if args.no_https else 443
server_port = server_port if not args.port else args.port
httpd = HTTPServer(('0.0.0.0', server_port), MyHTTPHandler)

if not args.no_https:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=args.cert_file, keyfile=args.key_file)
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

httpd.serve_forever()


