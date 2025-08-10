from ast import arg
from math import e
from socket import timeout
from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console

#Rich Console
console = Console()

#Arguement Parser
parser = argparse.ArgumentParser()

parser.add_argument('-l', '--list', help='To provide list of urls as an input')
parser.add_argument('-u', '--url', help='To provide single url as an input')
parser.add_argument('-p', '--payloads', help='To provide payload file having Blind SQL Payloads with delay of 30 sec', required=True)
parser.add_argument('-H', '--headers', help='To provide header file having HTTP Headers which are to be injected', required=True)
parser.add_argument('-v', '--verbose', help='Run on verbose mode', action='store_true')
parser.add_argument('-c', '--cookie', help='Cookie string to include in requests', required=False)
parser.add_argument('-pp', '--proxy', help='Proxy string (e.g., socks5://127.0.0.1:9050)', required=False)
args = parser.parse_args()

#Header Payload Creation

# Open the Payloads file and read its contents into a list
try:
   with open(args.payloads, 'r') as file:
      payloads = [line.strip() for line in file]
except FileNotFoundError as e:
   print(str(e))
except PermissionError as e:
   print(str(e))
except IOError as e:
   print(str(e))

# Open the Headers file and read its contents into a list
try:
   with open(args.headers, 'r') as file:
      headers = [line.strip() for line in file]
except FileNotFoundError as e:
   print(str(e))
except PermissionError as e:
   print(str(e))
except IOError as e:
   print(str(e))




# Function to sanitize all non-ASCII characters and ensure valid header values
import re
from urllib.parse import quote
def sanitize_ascii(s):
    # Remove non-ASCII characters
    s = ''.join(c for c in s if ord(c) < 128)
    # Collapse multiple spaces
    s = re.sub(r' +', ' ', s)
    # Strip leading/trailing spaces
    return s.strip()


headers_list = []
for header in headers:
    sanitized_header = sanitize_ascii(header)
    for payload in payloads:
        sanitized_payload = sanitize_ascii(payload)
        var = sanitized_header + ": " + sanitized_payload
        headers_list.append(var)

headers_dict = {header: header.split(": ")[1] for header in headers_list}

def add_cookie_to_header(header_dict):
    if args.cookie:
        header_dict['Cookie'] = args.cookie
    return header_dict

def get_client():
    if args.proxy:
        return httpx.Client(timeout=60, proxy=args.proxy, verify=False)
    else:
        return httpx.Client(timeout=60)

#For File as an Input
def onfile():
   # Open the URL file and read its contents into a list
   with open(args.list, 'r') as file:
      urls = [line.strip() for line in file]

   for url in urls:
      for header in headers_dict:
         cust_header = {header.split(": ")[0]: header.split(": ")[1]}
         cust_header = add_cookie_to_header(cust_header)
         try:
            with get_client() as client:
               response = client.get(url, headers=cust_header, follow_redirects=True)
            res_time=response.elapsed.total_seconds()

            if res_time >=float(25) and res_time <=float(50):
               console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
               console.print ("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
               console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))
               console.print("🐞 [bold][cyan]Status: [/][red]Vulnerable[/][/]")
               print()
         except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError) as e:
            print(f"The request was not successful due to: {e}")
            print()
            pass       
         
#For File as an Input-Verbose
def onfile_v():
   # Open the UR file and read its contents into a list
   with open(args.list, 'r') as file:
       urls = [line.strip() for line in file]

   for url in urls:
      for header in headers_dict:
         cust_header = {header.split(": ")[0]: header.split(": ")[1]}
         cust_header = add_cookie_to_header(cust_header)
         console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
         console.print ("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
         try:
            with get_client() as client:
               response = client.get(url, headers=cust_header, follow_redirects=True)
            console.print("🔢 [bold][cyan]Status code: [/][/]", response.status_code)
            res_time=response.elapsed.total_seconds()
            console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))

            if res_time >=float(25) and res_time <=float(50):
               console.print("[🐞bold][cyan]Status: [/][red]Vulnerable[/][/]" )
               print()
            else:
               console.print ("🐞[bold][cyan]Status: [/][green]Not Vulnerable[/][/]")
               print()
         except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError) as e:
            print(f"The request was not successful due to: {e}")
            print()
            pass 

#For URL as an Input
def onurl():
   # Save URL as Variable
   url = args.url

   for header in headers_dict:
      cust_header = {header.split(": ")[0]: header.split(": ")[1]}
      cust_header = add_cookie_to_header(cust_header)
      try:
         with get_client() as client:
            response = client.get(url, headers=cust_header, follow_redirects=True)
         res_time=response.elapsed.total_seconds()

         if res_time >=float(25) and res_time <=float(50):
            console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
            console.print ("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
            console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))
            console.print("🐞 [bold][cyan]Status: [/][red]Vulnerable[/][/]")
            print()       
      except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError) as e:
         print(f"The request was not successful due to: {e}")
         print()
         pass 
        
#For URL as an Input-Verbose
def onurl_v():
   #Save URL as Variable
   url = args.url

   for header in headers_dict:
      cust_header = {header.split(": ")[0]: header.split(": ")[1]}
      cust_header = add_cookie_to_header(cust_header)
      console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
      console.print ("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
      try:
         with get_client() as client:
            response = client.get(url, headers=cust_header, follow_redirects=True)
         console.print("🔢 [bold][cyan]Status code: [/][/]", response.status_code)
         res_time=response.elapsed.total_seconds()
         console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))

         if res_time >=float(25) and res_time <=float(50):
            console.print("🐞 [bold][cyan]Status: [/][red]Vulnerable[/][/]")
            print()
         else:
            console.print ("🐞[bold][cyan]Status: [/][green]Not Vulnerable[/][/]")
            print()        
      except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError) as e:
         print(f"The request was not successful due to: {e}")
         print()
         pass         

#Banner
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

if args.url != None:
   if args.verbose:
      onurl_v()
   else:
      onurl()
elif args.list != None:
   if args.verbose:
      onfile_v()
   else:
      onfile()
else:
   print("Error: One out of the two flag -u or -l is required")
