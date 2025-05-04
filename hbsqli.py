from http.cookies import SimpleCookie
import httpx
import argparse
from rich.console import Console

# Rich Console
console = Console()

# Argument Parser
parser = argparse.ArgumentParser()
parser.add_argument('-l', '--list', help='List of URLs as input')
parser.add_argument('-u', '--url', help='Single URL as input')
parser.add_argument('-p', '--payloads', help='Payload file for Blind SQLi', required=True)
parser.add_argument('-H', '--headers', help='Header file for injection', required=True)
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
parser.add_argument('--cookie', help='Cookie string for requests')
parser.add_argument('-pp', '--proxy', help='SOCKS5 proxy (e.g., socks5://127.0.0.1:9050)')
args = parser.parse_args()

# Statistics
total_tests = 0
vulnerable_urls = set()
vulnerable_tests = 0

def load_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8', errors='replace') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Error loading {filename}: {e}[/]")
        exit(1)

# Load payloads and headers
payloads = load_file(args.payloads)
headers = load_file(args.headers)

# Prepare headers with payloads
headers_dict = {}
for header in headers:
    for payload in payloads:
        headers_dict[f"{header}: {payload}"] = payload

# Parse cookies
cookies = {}
if args.cookie:
    try:
        cookie = SimpleCookie()
        cookie.load(args.cookie.replace('\\', ''))  # Clean cookie string
        cookies = {k: v.value for k, v in cookie.items()}
    except Exception as e:
        console.print(f"[yellow]Warning: Invalid cookie format: {e}[/]")

# Configure transport
transport = None
if args.proxy:
    try:
        transport = httpx.HTTPTransport(proxy=args.proxy)
    except Exception as e:
        console.print(f"[yellow]Warning: Proxy setup failed: {e}[/]")

def sanitize_header_value(value):
    """Ensure header values are ASCII-compatible"""
    return value.encode('ascii', 'replace').decode('ascii')

def make_request(url, header_key):
    global total_tests, vulnerable_urls, vulnerable_tests
    
    total_tests += 1
    try:
        header_name, header_value = header_key.split(": ", 1)
        headers = {header_name: sanitize_header_value(header_value)}
        
        with httpx.Client(
            timeout=30,
            cookies=cookies,
            transport=transport,
            follow_redirects=True
        ) as client:
            response = client.get(url, headers=headers)
            res_time = response.elapsed.total_seconds()
            
            if 25 <= res_time <= 50:
                vulnerable_urls.add(url)
                vulnerable_tests += 1
                return True, res_time
            return False, res_time
    except Exception as e:
        if args.verbose:
            console.print(f"[yellow]Request failed: {str(e)}[/]")
        return None, 0

def test_url(url):
    for header in headers_dict:
        if args.verbose:
            console.print(f"🌐 [cyan]Testing URL:[/] {url}")
            console.print(f"💉 [cyan]Testing Header:[/] {repr(header)}")
        
        is_vuln, res_time = make_request(url, header)
        
        if args.verbose:
            if is_vuln is None:
                console.print(f"[red]Request failed[/]")
            else:
                console.print(f"⏱️ [cyan]Response Time:[/] {res_time:.2f}s")
                status = "[red]Vulnerable[/]" if is_vuln else "[green]Not Vulnerable[/]"
                console.print(f"🐞 [cyan]Status:[/] {status}")
            print()

def print_stats():
    console.print("\n[bold]===== Results =====[/]")
    console.print(f"🔢 [cyan]Total tests:[/] {total_tests}")
    console.print(f"⚠️  [cyan]Vulnerable URLs:[/] {len(vulnerable_urls)}")
    console.print(f"💉 [cyan]Vulnerable tests:[/] {vulnerable_tests}")
    
    if vulnerable_urls:
        save = input("\nSave vulnerable URLs? (y/n): ").lower()
        if save == 'y':
            filename = input("Filename: ")
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("\n".join(vulnerable_urls))
                console.print(f"[green]Saved to {filename}[/]")
            except Exception as e:
                console.print(f"[red]Error saving file: {e}[/]")

# Banner (fixed escape sequences)
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

# Main execution
if args.url:
    test_url(args.url)
elif args.list:
    try:
        urls = load_file(args.list)
        for url in urls:
            test_url(url)
    except Exception as e:
        console.print(f"[red]Error reading URL list: {e}[/]")
else:
    console.print("[red]Error: Provide either -u or -l option[/]")

print_stats()
