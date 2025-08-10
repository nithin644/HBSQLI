
# HBSQLI: Automated Tester For Header Based Blind SQL Injection

HBSQLI is an automated command-line tool for performing Header Based Blind SQL injection attacks on web applications. It automates the process of detecting Header Based Blind SQL injection vulnerabilities, making it easier for security researchers , penetration testers & bug bounty hunters to test the security of web applications.
![image](https://github.com/user-attachments/assets/70a158ac-60f7-4292-968b-d0316e041a99)

### Disclaimer:
This tool is intended for authorized penetration testing and security assessment purposes only. Any unauthorized or malicious use of this tool is strictly prohibited and may result in legal action.

The authors and contributors of this tool do not take any responsibility for any damage, legal issues, or other consequences caused by the misuse of this tool. The use of this tool is solely at the user's own risk.

Users are responsible for complying with all applicable laws and regulations regarding the use of this tool, including but not limited to, obtaining all necessary permissions and consents before conducting any testing or assessment.

By using this tool, users acknowledge and accept these terms and conditions and agree to use this tool in accordance with all applicable laws and regulations.
## Installation

Install HBSQLI with following steps:

```bash
$ git clone https://github.com/SAPT01/HBSQLI.git
$ cd HBSQLI
$ chmod +x hbsqli.py
$ pip3 install -r requirements.txt 
```
    
## Usage/Examples

```javascript
usage: hbsqli.py [-h] [-l LIST] [-u URL] -p PAYLOADS -H HEADERS [-v] [--cookie COOKIE] [-pp PROXY]

options:
  -h, --help            show this help message and exit
  -l, --list LIST       List of URLs as input
  -u, --url URL         Single URL as input
  -p, --payloads PAYLOADS
                        Payload file for Blind SQLi
  -H, --headers HEADERS
                        Header file for injection
  -v, --verbose         Verbose mode
  --cookie COOKIE       Cookie string for requests
  -pp, --proxy PROXY    SOCKS5 proxy (e.g., socks5://127.0.0.1:9050)

```
### For Single URL:
```javascript
$ python3 hbsqli.py -u "https://target.com" -p payloads.txt -H headers.txt -v -pp <proxy-if-u-need>
```
### For List of URLs:
```javascript
$ python3 hbsqli.py -l urls.txt -p payloads.txt -H headers.txt -v
```
### Modes
There are basically two modes in this, **verbose** which will show you all the process which is happening and show your the status of each test done and **non-verbose**, which will just print the vulnerable ones on the screen.
To initiate the verbose mode just add **-v** in your command

### Notes
* You can use the provided payload file or use a custom payload file, just remember that delay in each payload in the payload file should be set to **30 seconds**.

* You can use the provided headers file or even some more custom header in that file itself according to your need.
## Demo

<video src="https://github.com/user-attachments/assets/9bc38aaa-c0d5-43ef-a405-78f0574f3c21" controls width="600"></video>
