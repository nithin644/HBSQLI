from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console
import re
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rich Console
console = Console()

# Argument Parser
parser = argparse.ArgumentParser()

parser.add_argument('-l', '--list', help='To provide list of urls as an input')
parser.add_argument('-u', '--url', help='To provide single url as an input')
parser.add_argument('-p', '--payloads', help='Payload file having Blind SQL Payloads', required=True)
parser.add_argument('-H', '--headers', help='Header file having HTTP Headers', required=True)
parser.add_argument('-v', '--verbose', help='Run in verbose mode', action='store_true')
parser.add_argument('-c', '--cookie', help='Cookie string to include in requests')
parser.add_argument('-pp', '--proxy', help='Proxy string (e.g., socks5://127.0.0.1:9050)')
parser.add_argument('-t', '--threads', help='Number of concurrent threads (default=5)', type=int, default=5)
parser.add_argument('--delay-min', help='Minimum delay threshold in seconds (default=25)', type=int, default=25)
parser.add_argument('--delay-max', help='Maximum delay threshold in seconds (default=50)', type=int, default=50)
parser.add_argument('--no-urlencode', help='Disable URL encoding of payloads', action='store_true')

args = parser.parse_args()

# Load payloads
try:
    with open(args.payloads, 'r') as file:
        payloads = [line.strip() for line in file]
except Exception as e:
    console.print(f"[red]Error reading payload file: {e}[/]")
    exit(1)

# Load headers
try:
    with open(args.headers, 'r') as file:
        headers = [line.strip() for line in file]
except Exception as e:
    console.print(f"[red]Error reading headers file: {e}[/]")
    exit(1)

# Sanitize non-ASCII
def sanitize_ascii(s):
    s = ''.join(c for c in s if ord(c) < 128)
    s = re.sub(r' +', ' ', s)
    return s.strip()

# Prepare headers + payloads
headers_list = []
for header in headers:
    sanitized_header = sanitize_ascii(header)
    for payload in payloads:
        sanitized_payload = sanitize_ascii(payload)
        if args.no_urlencode:
            final_payload = sanitized_payload
        else:
            final_payload = quote(sanitized_payload)   # URL encode
        var = sanitized_header + ": " + final_payload
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

# === Global tracking ===
total_tests = 0
vulnerable_results = []

# === Test Function ===
def test_header(url, header, verbose=False):
    global total_tests, vulnerable_results
    cust_header = {header.split(": ")[0]: header.split(": ")[1]}
    cust_header = add_cookie_to_header(cust_header)

    try:
        with get_client() as client:
            response = client.get(url, headers=cust_header, follow_redirects=True)
        res_time = response.elapsed.total_seconds()
        total_tests += 1

        if verbose:
            console.print("🌐 [cyan]Testing URL:[/] ", url)
            console.print("💉 [cyan]Testing Header:[/] ", repr(header))
            console.print("🔢 [cyan]Status code:[/] ", response.status_code)
            console.print("⏱️ [cyan]Response Time:[/] ", repr(res_time))

        if args.delay_min <= res_time <= args.delay_max:
            console.print("🐞 [cyan]Status:[/] [red]Vulnerable[/]")
            vulnerable_results.append((url, header, res_time))
        else:
            if verbose:
                console.print("🐞 [cyan]Status:[/] [green]Not Vulnerable[/]")

    except Exception as e:
        if verbose:
            console.print(f"[yellow]Request error: {e}[/]")

# === Banner ===
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

# === Run Tests ===
def run_scans(urls):
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for url in urls:
            for header in headers_dict:
                futures.append(executor.submit(test_header, url, header, args.verbose))
        for _ in as_completed(futures):
            pass

if args.url:
    run_scans([args.url])
elif args.list:
    try:
        with open(args.list, 'r') as file:
            urls = [line.strip() for line in file]
        run_scans(urls)
    except Exception as e:
        console.print(f"[red]Error reading URL list: {e}[/]")
else:
    console.print("[red]Error: One out of the two flags -u or -l is required[/]")

# === Final Summary ===
console.print("\n[bold cyan]=== Scan Summary ===[/]")
console.print(f"📊 Total tests run: [yellow]{total_tests}[/]")
console.print(f"🐞 Vulnerable findings: [red]{len(vulnerable_results)}[/]")

# Ask to save results
if vulnerable_results:
    save = input("💾 Do you want to save vulnerable results to a file? (y/n): ").strip().lower()
    if save == "y":
        filename = input("Enter filename (default=vulnerable.txt): ").strip()
        if not filename:
            filename = "vulnerable.txt"
        with open(filename, "w") as f:
            for url, header, res_time in vulnerable_results:
                f.write(f"{url} | {header} | Response Time: {res_time}s\n")
        console.print(f"[green]✅ Vulnerable results saved to {filename}[/]")
