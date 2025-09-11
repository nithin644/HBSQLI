from ast import arg
from math import e
from socket import timeout
from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console
import re
from urllib.parse import quote

# Rich Console
console = Console()

# Argument Parser
parser = argparse.ArgumentParser()

parser.add_argument('-l', '--list', help='To provide list of urls as an input')
parser.add_argument('-u', '--url', help='To provide single url as an input')
parser.add_argument('-p', '--payloads', help='To provide payload file having Blind SQL Payloads with delay of 30 sec', required=True)
parser.add_argument('-H', '--headers', help='To provide header file having HTTP Headers which are to be injected', required=True)
parser.add_argument('-v', '--verbose', help='Run on verbose mode', action='store_true')
parser.add_argument('-c', '--cookie', help='Cookie string to include in requests', required=False)
parser.add_argument('-pp', '--proxy', help='Proxy string (e.g., socks5://127.0.0.1:9050)', required=False)
args = parser.parse_args()

# Load payloads
try:
    with open(args.payloads, 'r') as file:
        payloads = [line.strip() for line in file]
except Exception as e:
    print(f"Error reading payload file: {e}")
    exit(1)

# Load headers
try:
    with open(args.headers, 'r') as file:
        headers = [line.strip() for line in file]
except Exception as e:
    print(f"Error reading headers file: {e}")
    exit(1)

# Sanitize non-ASCII
def sanitize_ascii(s):
    s = ''.join(c for c in s if ord(c) < 128)   # Remove non-ASCII
    s = re.sub(r' +', ' ', s)                  # Collapse multiple spaces
    return s.strip()

# Prepare headers + URL encode payloads
headers_list = []
for header in headers:
    sanitized_header = sanitize_ascii(header)
    for payload in payloads:
        sanitized_payload = sanitize_ascii(payload)
        encoded_payload = quote(sanitized_payload)   # URL encode here 🔥
        var = sanitized_header + ": " + encoded_payload
        headers_list.append(var)

headers_dict = {header: header.split(": ")[1] for header in headers_list}

# Add cookie if given
def add_cookie_to_header(header_dict):
    if args.cookie:
        header_dict['Cookie'] = args.cookie
    return header_dict

# Create client (with or without proxy)
def get_client():
    if args.proxy:
        return httpx.Client(timeout=60, proxy=args.proxy, verify=False)
    else:
        return httpx.Client(timeout=60)

# === Functions for testing ===
def test_url(url, verbose=False):
    for header in headers_dict:
        cust_header = {header.split(": ")[0]: header.split(": ")[1]}
        cust_header = add_cookie_to_header(cust_header)
        if verbose:
            console.print("🌐 [cyan]Testing URL:[/] ", url)
            console.print("💉 [cyan]Testing Header:[/] ", repr(header))
        try:
            with get_client() as client:
                response = client.get(url, headers=cust_header, follow_redirects=True)
            res_time = response.elapsed.total_seconds()
            if verbose:
                console.print("🔢 [cyan]Status code:[/] ", response.status_code)
                console.print("⏱️ [cyan]Response Time:[/] ", repr(res_time))

            if res_time >= 25 and res_time <= 50:
                console.print("🐞 [cyan]Status:[/] [red]Vulnerable[/]")
            else:
                if verbose:
                    console.print("🐞 [cyan]Status:[/] [green]Not Vulnerable[/]")
        except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError) as e:
            print(f"The request was not successful due to: {e}")
            pass
        print()

# === Main Logic ===
console.print('''[royal_blue1]                
   ▄█    █▄    ▀█████████▄     ▄████████ ████████▄    ▄█        ▄█  
  ███    ███     ███    ███   ███    ███ ███    ███  ███       ███  
  ███    ███     ███    ███   ███    █▀  ███    ███  ███       ███▌ 
 ▄███▄▄▄▄███▄▄  ▄███▄▄▄██▀    ███        ███    ███  ███       ███▌ 
▀▀███▀▀▀▀███▀  ▀▀███▀▀▀██▄  ▀███████████ ███    ███  ███       ███▌ 
  ███    ███     ███    ██▄          ███ ███    ███  ███       ███  
  ███    ███     ███    ███    ▄█    ███ ███  ▀ ███  ███▌    ▄ ███  
  ███    █▀    ▄█████████▀   ▄████████▀   ▀██████▀▄█ █████▄▄██ █▀   
                                                     ▀           [/] 
                                                [bold][wheat1]Created By[/][orange3] @Nithin Palegar[/]                
''')

if args.url:
    test_url(args.url, verbose=args.verbose)
elif args.list:
    try:
        with open(args.list, 'r') as file:
            urls = [line.strip() for line in file]
        for url in urls:
            test_url(url, verbose=args.verbose)
    except Exception as e:
        print(f"Error reading URL list: {e}")
else:
    print("Error: One out of the two flags -u or -l is required")
