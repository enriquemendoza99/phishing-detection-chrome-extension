import requests

url_to_test = "http://paypal-fake-lookout//login.com"

res = requests.post("http://localhost:5000/check", json={"url": url_to_test})

print("Response from Flask API:", res.json())
