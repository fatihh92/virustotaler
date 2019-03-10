import requests, json
import argparse,os


def url(link):
    params = {'apikey': 'api_key', 'url': link}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    results = response.json()
    print("REPORT")
    params2 = {'apikey': 'api_key',
               'resource': results['scan_id']}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params2)
    results2 = json.loads(response.text)
    print("TOTAL : ", results2['total'])
    print("POSİTİVES : ", results2['positives'])
    if results2['positives'] == 0:
        print("The url is clear")
    else:
        print(json.dumps(results2["scans"], indent=4))


def file(file):
    params = {'apikey': 'api_key'}
    files = {'file': (file, open(file, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    results = response.json()
    print("REPORT")
    params = {'apikey': 'api_key',
              'resource': results['scan_id']}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    results2 = json.loads(response.text)
    print("TOTAL : ", results2['total'])
    print("POSİTİVES : ", results2['positives'])
    if results2['positives'] == 0:
        print("The file is clear")
    else:
        print(json.dumps(results2["scans"], indent=4))


def ip(IP):
    params = {'apikey': 'api_key', 'ip': IP}
    response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params)
    results= json.loads(response.text)
    print("#"*50,"> IP INFO <",'#'*50)
    print("NETWORK : ",results["network"])
    print("COUNTRY : ",results["country"])
    print("OWNER : ",results["as_owner"])
    print("CONTINENT : ",results["continent"])
    print("#"*50,"> HOSTNAMES (",len(results["resolutions"]),") <","#"*50)
    for i in results["resolutions"]:
        print("HOSTNAME : ",i['hostname'])
    print("#"*50,"> UNDETECTED URLS (",len(results["undetected_urls"]),") <","#"*50)# burayı düzenle
    for i in results["undetected_urls"]:
        print(i,"\n")
        print("-"*100)
    print("#" * 50, "> DETECTED URLS (",len(results["detected_urls"]),") <", "#" * 50)
    for i in results["detected_urls"]:
        print("URL : ",i['url'])
        print("POSITIVES : ",i['positives'])
        print("TOTAL : ",i['total'])
        print("SCAN DATE : ",i['scan_date'])
        print("-"*100)

def domain(dmn):
    params = {'apikey': 'api_key', 'domain': dmn}
    response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params)
    results=json.loads(response.text)
    print("#"*50,"> IP ADDRESS (",len(results["resolutions"]),") <","#"*50)
    j = []
    for i in results["resolutions"]:
        j.append(i['ip_address'])
    j.sort()
    for k in j:
        print(k)
    print("#"*50,"> SUBDOMAINS (",len(results['domain_siblings']),") <","#"*50)
    for i in results['domain_siblings']:
        print(i)
    print("#"*50,"> WHOIS <","#"*50)
    print(results["whois"])
    print("#"*50,"> ALEXA RANK <","#"*50)
    try:
        print("Alexa Rank: ",json.dumps(results["Alexa rank"]))
    except:
        print("Alexa is not exist")
    print("#"*50,"> SAFETY SCORE <","#"*50)
    try:
        print("Safety Score: ",results["Webutation domain info"]["Safety score"])
    except:
        print("Safety score is not exist")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", "-u", help="Enter an url like http://www.example.com")
    parser.add_argument("--file", "-f", help="Enter a path of file")
    parser.add_argument("--ip", "-p", help="Enter an ip")
    parser.add_argument("--domain", "-d", help="Enter a domain like www.example.com")
    data = parser.parse_args()

    if data.url is not None:
        url(data.url)
    elif data.file is not None:
        file(data.file)
    elif data.ip is not None:
        ip(data.ip)
    elif data.domain is not None:
        domain(data.domain)


if __name__ == '__main__':
    if os.name == 'nt':
        os.system("cls")
    elif os.name == 'Linux':
        os.system("clear")
    main()
