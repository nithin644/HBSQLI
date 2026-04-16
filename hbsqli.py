from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console
import re
from urllib.parse import quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading  # FIX 1: for thread-safe lock

# optional socks support for httpx proxies
try:
    import socksio  # httpx requires this for SOCKS proxies
except ImportError:
    socksio = None

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

# FIX 3: URL validation function
def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

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

# FIX 2: Thread-local storage for per-thread reusable httpx client
_thread_local = threading.local()

def get_client():
    # httpx needs the socksio package when using a socks proxy.
    if args.proxy and args.proxy.lower().startswith("socks") and not socksio:
        console.print("[red]Error:[/] SOCKS proxy requested but the 'socksio' package is not installed.\n"
                      "Install it via `pip install socksio` or `pip install httpx[socks]` and try again.")
        exit(1)

    # Reuse existing client for this thread if already created
    if not hasattr(_thread_local, "client") or _thread_local.client.is_closed:
        if args.proxy:
            _thread_local.client = httpx.Client(timeout=60, proxy=args.proxy, verify=False)
        else:
            _thread_local.client = httpx.Client(timeout=60)

    return _thread_local.client

# FIX 1: Thread-safe lock + counters
_lock = threading.Lock()
total_tests = 0
vulnerable_results = []

# === Test Function ===
def test_header(url, header, verbose=False):
    global total_tests, vulnerable_results
    cust_header = {header.split(": ")[0]: header.split(": ")[1]}
    cust_header = add_cookie_to_header(cust_header)

    try:
        client = get_client()
        response = client.get(url, headers=cust_header, follow_redirects=True)
        res_time = response.elapsed.total_seconds()

        # FIX 1: Use lock when modifying shared state
        with _lock:
            total_tests += 1

        if verbose:
            console.print("🌐 [cyan]Testing URL:[/] ", url)
            console.print("💉 [cyan]Testing Header:[/] ", repr(header))
            console.print("🔢 [cyan]Status code:[/] ", response.status_code)
            console.print("⏱️ [cyan]Response Time:[/] ", repr(res_time))

        # consider a test vulnerable if it falls within the configured window
        # *or* if the response is delayed at least an additional 10 seconds beyond the
        # upper threshold (payloads that sleep 10s+ would trigger this).
        extra_delay = 10.0
        if (args.delay_min <= res_time <= args.delay_max) or (res_time >= args.delay_max + extra_delay):
            console.print(f"🐞 [cyan]Status:[/] [red]Vulnerable[/] — URL: [bold]{url}[/], Header: [bold]{header}[/], Response Time: [yellow]{res_time}s[/]")
            # FIX 1: Use lock when modifying shared list
            with _lock:
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

    # FIX 2: Close all thread-local clients after scan completes
    # (clients are cleaned up when threads are destroyed by the executor)

if args.url:
    # FIX 3: Validate single URL
    if not is_valid_url(args.url):
        console.print(f"[red]Invalid URL: {args.url} — must start with http:// or https://[/]")
        exit(1)
    run_scans([args.url])

elif args.list:
    try:
        with open(args.list, 'r') as file:
            raw_urls = [line.strip() for line in file if line.strip()]

        # FIX 3: Validate URLs
        valid_urls = []
        skipped = 0
        for u in raw_urls:
            if is_valid_url(u):
                valid_urls.append(u)
            else:
                console.print(f"[yellow]⚠ Skipping invalid URL: {u}[/]")
                skipped += 1

        # FIX 4: Deduplicate URLs while preserving order
        seen = set()
        unique_urls = []
        for u in valid_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        duplicates_removed = len(valid_urls) - len(unique_urls)
        if duplicates_removed > 0:
            console.print(f"[yellow]⚠ Removed {duplicates_removed} duplicate URL(s)[/]")
        if skipped > 0:
            console.print(f"[yellow]⚠ Skipped {skipped} invalid URL(s)[/]")

        if not unique_urls:
            console.print("[red]No valid URLs to scan. Exiting.[/]")
            exit(1)

        console.print(f"[green]✅ Scanning {len(unique_urls)} unique valid URL(s)[/]")
        run_scans(unique_urls)

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
    console.print("\n[bold red]Detailed Vulnerable Results:[/]")
    for url, header, res_time in vulnerable_results:
        console.print(f"- [bold]{url}[/] | {header} | Response Time: [yellow]{res_time}s[/]")
    save = input("💾 Do you want to save vulnerable results to a file? (y/n): ").strip().lower()
    if save == "y":
        filename = input("Enter filename (default=vulnerable.txt): ").strip()
        if not filename:
            filename = "vulnerable.txt"
        with open(filename, "w") as f:
            for url, header, res_time in vulnerable_results:
                f.write(f"{url} | {header} | Response Time: {res_time}s\n")
        console.print(f"[green]✅ Vulnerable results saved to {filename}[/]")
