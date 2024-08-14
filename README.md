usage: https_logger.py [-h] [--no-https] [-p PORT] [--key-file KEY_FILE]
                       [--cert-file CERT_FILE]
                       [--server-version SERVER_VERSION]
                       [--sys-version SYS_VERSION] [-o LOG_FILE]
                       [--log-format {txt,json-txt,csv}] [--url-decode]
                       [-L REDIRECT | -f CONTENT_FILE]
                       [--redirect-code {301,302,303,307,308}] [-H ADD_HEADER]

Python simple HTTP server for different testing operations.

options:
  -h, --help            show this help message and exit
  -L REDIRECT, --redirect REDIRECT
                        URL to redirect user. Can be combined --redirect-code,
                        default https://example.com
  -f CONTENT_FILE, --content-file CONTENT_FILE
                        Return specified file content in response. Use-case:
                        empty html with meta tag/JS script can be used to
                        redirect user/collect additional info etc.
  --redirect-code {301,302,303,307,308}
  -H ADD_HEADER, --add-header ADD_HEADER
                        Add custom HTTP header to response. Overwrites other
                        parameters e.g -L https://example.com -H 'Location:
                        https://test.com' will results in redirection to
                        https://test.com

HTTP:
  Configure SSL usage and ports

  --no-https            Run HTTP, default HTTPs.
  -p PORT, --port PORT  Port to listen on, default 443 or 80 if --no-https
                        specified.
  --key-file KEY_FILE   File with private key, required for HTTPs.
  --cert-file CERT_FILE
                        File with server certificate, required for HTTPs.

Server Header:
  Configure Server Header, e.g. change Server: "BaseHTTP/0.6 Python/3.11.9"

  --server-version SERVER_VERSION
                        Default: Apache/2.4
  --sys-version SYS_VERSION
                        Default: ""

Logging:
  Configure logging

  -o LOG_FILE, --log-file LOG_FILE
                        Path to file where logs will be saved.
  --log-format {txt,json-txt,csv}
                        Format for logging.
  --url-decode          Use urllib to decode Headers and Body from Requests.
                        Default: False

EXAMPLES:
        https_logger.py --no-https
        https_logger.py --key-file /etc/letsencrypt/live/your_dom/privkey.pem --cert-file /etc/letsencrypt/live/your_dom/fullchain.pem
        https_logger.py --no-https -L https://example.com
        https_logger.py --no-https -L https://example.com --redirect-code 302
        https_logger.py --no-https -f ~/scripts/logger.html
        https_logger.py --no-https -o /tmp/logs.txt --log-format txt
        https_logger.py --no-https -f ~/scripts/logger.html -L https://example.com --redirect-code 302
REDIRECT:
        Read docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections
OUTPUT FORMATS EXAMPLES:
        txt: 
        127.0.0.1;40312;GET /adasdadafhtrewdfs HTTP/1.1
        json-txt:
                "{"Client IP": "127.0.0.1", "Client Port": 50622, "Request": "GET /sdfsdfdsfsdf HTTP/1.1", "Request Body": "", 
                "Request Headers": "Host: localhost\nUser-Agent: curl/8.7.1\nAccept: */*\n\n"}"
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
