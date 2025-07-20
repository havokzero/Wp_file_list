# CVE-2025-34085 - WordPress Simple File List Unauthenticated RCE

A proof-of-concept exploitation tool for **CVE-2025-34085**, an unauthenticated remote code execution vulnerability in the WordPress **Simple File List** plugin.

This vulnerability allows an attacker to upload a disguised PHP payload, rename it via a vulnerable endpoint, and execute arbitrary commands on the server.

---

## Description

This script targets WordPress installations running vulnerable versions of the Simple File List plugin. It performs the following actions:

1. Uploads a disguised PHP payload as an image using `ee-upload-engine.php`.
2. Renames the uploaded file to a `.php`, `.phtml`, or other executable extension using `ee-file-engine.php`.
3. Triggers command execution via the uploaded web shell.

Targets are entered interactively via the command line.

---

## Vulnerability Details

- **CVE ID:** CVE-2025-34085  
- **Plugin:** WordPress Simple File List  
- **Vulnerable Versions:** All versions prior to vendor patch  
- **Attack Vector:** Unauthenticated HTTP POST  
- **Impact:** Remote Code Execution (RCE)

---

## Requirements

- Python 3.6+
- `requests`
- `colorama`

Install requirements:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install requests colorama
```

---

## Usage

```bash
python3 wp_sfl_rce.py
```

You will be prompted to enter the target host and port.

---

## Example Output

```
Enter target IP or domain (or q to quit): example.com
Enter port (default 80): 80

[•] Targeting: http://example.com:80

[+] Exploited: http://example.com:80 | /wp-content/uploads/simple-file-list/xh3k.php | uid=33(www-data)
```

---

## Features

- Interactive CLI loop for single-target scanning
- Automatic payload generation and renaming
- Detection of successful RCE via command output
- Color-coded terminal output
- Logs vulnerable hosts to `vuln.txt`

---

## Limitations

- HTTPS with invalid certificates is not verified
- Only checks for successful `id` command execution
- Does not support proxies or SOCKS routing

---

## Legal Disclaimer

This tool is intended for **educational and authorized security testing only**.  
Do not use this tool on systems you do not own or have explicit permission to test.  
The developer assumes no liability for misuse or damage caused by this software.

---

## References

- [CVE-2025-34085 - MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-34085)
- Vendor advisory and patch information (pending release)
