import requests, sys, json, xmltodict
from pathlib import Path

requests.packages.urllib3.disable_warnings()

basePath = Path.home() / 'pyenv3.9' / 'panos'

headers = {
    'header-api-key': 'qpnzpzoam9__CEzZdnfHBw94NFpTtWWlE6kerZjwHrQbaUUfEWjP',
    'content-type': 'application/x-www-form-urlencoded',
}

if len(sys.argv) > 1:
    optionFile = f"{basePath}/data/{sys.argv[1]}"
else:
    optionFile = f"{basePath}/data/rj_prisma_options.txt"

outFile = f"{basePath}/reports/prisma_egress_ips.txt"

with open(optionFile) as f:
    data = f.read().replace('\n', '').replace('\r', '').encode()

response = requests.post('https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2', headers=headers, data=data, verify=False)

allow_list = []
print(response.json())
for each in response.json()['result']:
    for address in each['addresses']:
        allow_list.append(address)

with open (outFile, 'w') as f:
    f.write('\n'.join(allow_list))
