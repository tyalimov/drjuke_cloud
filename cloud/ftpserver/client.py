import requests
response = requests.get('http://127.0.0.1:9999')
print(response.content)