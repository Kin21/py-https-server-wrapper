```
usage: https_logger.py [-h] [--no-https] [-p PORT] [--key-file KEY_FILE]
                       [--cert-file CERT_FILE]
                       [--server-version SERVER_VERSION]
                       [--sys-version SYS_VERSION] [-o LOG_FILE]
                       [-of {txt,json-txt,csv}] [--url-decode] [-L REDIRECT]
                       [-f CONTENT_FILE] [-if INCLUDE_FILE] [-w ALLOWED_FILE]
                       [-id WWW] [--redirect-code {301,302,303,307,308}]
                       [-H ADD_HEADER]

Python simple HTTP server for different testing operations.

options:
  -h, --help            show this help message and exit
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
  -of {txt,json-txt,csv}, --log-format {txt,json-txt,csv}
                        Format for logging.
  --url-decode          Use urllib to decode Headers and Body from Requests.
                        Default: False

CONTENT CONTROL:
  -L REDIRECT, --redirect REDIRECT
                        URL to redirect user. Can be combined --redirect-code,
                        default https://example.com
  -f CONTENT_FILE, --content-file CONTENT_FILE
                        Return specified file content in response. It will be
                        default file to serve. Use-case: empty html with meta
                        tag/JS script can be used to redirect user/collect
                        additional info etc.
  -if INCLUDE_FILE, --include-file INCLUDE_FILE
                        Allow to serve this files if allowed.
  -w ALLOWED_FILE, --allowed-file ALLOWED_FILE
                        Read files allowed to serve from specified ALLOWED-
                        FILE
  -id WWW, --www WWW    Directory where allowed files located
  --redirect-code {301,302,303,307,308}

EXAMPLES:
        https_logger.py --no-https
        https_logger.py --key-file /etc/letsencrypt/live/your_dom/privkey.pem --cert-file /etc/letsencrypt/live/your_dom/fullchain.pem
        https_logger.py --no-https -L https://example.com
        https_logger.py --no-https -L https://example.com --redirect-code 302
        https_logger.py --no-https -f ~/scripts/logger.html
        https_logger.py --no-https -o /tmp/logs.txt --log-format txt
        https_logger.py --no-https -f ~/scripts/logger.html -L https://example.com --redirect-code 302
ALLOW MULTIPLE FILES TO BE SERVER:
        -f specified with combination of [-if, -w, -id] will be default file to serve if requested path not in allowed files. E.g index.html
        -if and -w can be used together.
        -id specified directory where files should be found. It will be appended to requested path to compare against allowed files.
        Examples:
                # Read allowed files that located in www folder, if requested path not found/allowed www/index.html will be served
                find www -type f > allowed_files
                python https_logger.py --no-https -o test.json -of json-txt  -f www/index.html -w allowed_files --www www
                # Allow file to be served from current folder.
                python /diskD/tools/pyhttps-server/https_logger.py --no-https -o test.json -of json-txt -if ./test.txt -if ./LICENSE

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
```
