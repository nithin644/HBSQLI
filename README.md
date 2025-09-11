
# HBSQLI: Automated Header-Based Blind SQL Injection Tester

**HBSQLI** is an automated command-line tool designed for detecting and exploiting **Header-Based Blind SQL Injection** vulnerabilities in web applications.  
It streamlines the testing process, making it a powerful utility for **security researchers**, **penetration testers**, and **bug bounty hunters**.

This version is **heavily modified** from the original [SAPT01/HBSQLI](https://github.com/SAPT01/HBSQLI) repository, with new features and enhancements for advanced testing workflows.

![HBSQLI Screenshot](https://github.com/user-attachments/assets/70a158ac-60f7-4292-968b-d0316e041a99)

---

## 🔹 New Features in This Version 
- **Cookie Injection Support** → Pass custom cookies with `--cookie` argument.
- **Proxy Support** → Use `--proxy` (`-pp`) to route traffic through SOCKS5 proxies.
- Improved **payload management** for flexible testing.
- Cleaner **verbose mode** output.
- Code optimizations and better error handling.

---

## ⚠ Disclaimer
This tool is intended **only for authorized penetration testing and security assessments**.  
Any **unauthorized** or **malicious** use is strictly prohibited and may result in legal consequences.

- You are solely responsible for compliance with all **applicable laws**.
- The authors take **no responsibility** for misuse, damages, or legal issues caused.
- Obtain **written permission** before testing any system.

By using this tool, you agree to these terms.

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
usage: hbsqli.py [-h] [-l LIST] [-u URL] -p PAYLOADS -H HEADERS [-v] [--cookie COOKIE] [-pp PROXY] [-t threads]

options:
-l, --list  To provide list of urls as an input
-u, --url   To provide single url as an input
-p, --payloads  Payload file having Blind SQL Payloads
-H, --headers Header file having HTTP Headers
-v, --verbose  help='Run in verbose mode'
-c, --cookie  help='Cookie string to include in requests')
-pp, --proxy Proxy string (e.g., socks5://127.0.0.1:9050)
-t, --threads help='Number of concurrent threads (default=5)
--delay-min  Minimum delay threshold in seconds (default=25)
--delay-max  Maximum delay threshold in seconds (default=50)
--no-urlencode  Disable URL encoding of payloads


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
