from flask import Flask, jsonify
import difflib
import requests
import hashlib
import re
import urllib
import socket

app = Flask(__name__)

@app.route('/proxyCheckerAPI/check/<string:proxy>/', methods=['GET'])
def flaskProxyVerify(proxy):
    proxy = urllib.unquote(proxy).decode('ascii')
    return jsonify(verifyProxy(proxy))

def isPortOpen(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except:
        return False

def verifyProxy(proxyIP):
    if isPortOpen(proxyIP.split(':')[0],proxyIP.split(':')[1]):
        try:
            html = requests.get("http://www.daviddworken.com/", timeout=10, proxies = {'http':'http://'+proxyIP}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
        except:
            print proxyIP + " Status: 0"
            return {"Status:" : 0, "Reason": "Proxy not responding to requests"}
    else:
        print proxyIP + " Status: 0"
        return {"Status:" : 0, "Reason": "Proxy not responding to requests"}

    try:
        proxyHTML = requests.get("http://www.daviddworken.com/", proxies = {'http':'http://'+proxyIP}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
        normalHTML = requests.get(proxyIP, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
        if normalHTML.content == proxyHTML.content:
            print proxyIP + " Status: 4"
            return {"Status:" : 4, "Reason": "The proxy is not a proxy, it is just a web server"}
        print normalHTML.content
        print proxyHTML.content
    except:
        pass

    urls = ["http://www.daviddworken.com/", "http://google.com/", "http://dyn.com"]
    for url in urls:
        html = requests.get(url, proxies = {'http':'http://'+proxyIP}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
        differ = difflib.Differ()
        htmlNormal = requests.get(url)
        htmlHash = hashlib.sha1(html.content).digest()
        htmlNormalHash = hashlib.sha1(htmlNormal.content).digest()
        if(not(htmlHash == htmlNormalHash)):
            htmlNormalL = htmlNormal.content.splitlines()
            htmlL = html.content.splitlines()
            diff = differ.compare(htmlNormalL, htmlL)
            #print(bcolors.WARNING + "[-] Malicious proxy found at " + proxy + bcolors.ENDC)
            #diffOut =  '\n'.join(diff)
            print proxyIP + " Status: 1"
            return {"Status:" : 1, "Reason": "Proxy modifies HTML"}
    try:
        html = requests.get("https://example.com", proxies = {'http':'http://'+proxyIP}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
    except:
        print proxyIP + " Status: 2"
        return {"Status:" : 2, "Reason": "Proxy fails to connect over SSL (MITM attack is likely)"}
    try:
        html = requests.get("http://whatismyipaddress.com/proxy-check", proxies = {'http':'http://'+proxyIP}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
        if len([m.start() for m in re.finditer('FALSE', html.content)]) != 6 and 'TRUE' in html.content:
            print proxyIP + " Status: 3"
            return {"Status:" : 3, "Reason": "Proxy is not fully anonymous. "}
    except:
        pass
    print proxyIP + " Status: -1"
    return {"Status:" : -1, "Reason": "Proxy passed all tests"}

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=True)
