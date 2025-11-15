#!/usr/bin/python
import requests, xmltodict, os, calendar, datetime, argparse, yaml, getpass
import pandas as pd
from xlsxwriter import Workbook
from xlsxwriter.color import Color
from pathlib import Path
import xml.etree.ElementTree as ET

def getAPIKey(panLogin):
    requests.packages.urllib3.disable_warnings()
    try:
        # get API key from PANOS
        data = {
            'type': 'keygen',
            'user': panLogin['username'],
            'password': panLogin['password']
        }
        getAPIKeyRequest = requests.post(f"https://{panLogin['host']}/api/", data=data, verify=False)
        getAPIKeyRequest.raise_for_status()
        apiKeyDict = xmltodict.parse(getAPIKeyRequest.content)
        apiKey = apiKeyDict['response']['result']['key']
        return apiKey
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as error:
        print(error)
        pass

def runner():
    class DEVICE(object):
        def __init__(self, host='', username ='', password=''):
            self.host = host
            self.username = username
            self.password = password
    class PASSWORD(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--u', help='Username', type=str
    )
    parser.add_argument(
        '--p', help='Password', action=PASSWORD, nargs='?', dest='password', required=True
    )
    parser.add_argument(
        '--d', help='The YAML file of PA NGFWs', type=str, required=True
    )
    args = parser.parse_args()
    if args.u:
        username = args.u
    else:
        username = os.getlogin().split('@')[0]
    password = args.password
    basePath = Path.home() / 'pyenv3.9' / 'panos'
    devFile = f"{basePath}/data/{args.d}"
    dateStamp = datetime.datetime.now().strftime("%Y-%m-%d")
    logFile = f"{basePath}/logs/pa_cert_validation_log_{dateStamp}.txt"
    reportFile = f"{basePath}/reports/pa_cert_report_{dateStamp}.xlsx"
    
    with open(devFile) as f:
        devices = yaml.safe_load(f)

    months = {month: index for index, month in enumerate(calendar.month_abbr) if month}
    certificates = []
    completed = []
    failed = []
    
    for dev in devices['pafw']:
        device = DEVICE(dev['ip'], username, password)
        panLogin = {
            'host': device.host,
            'username': device.username,
            'password': device.password,
        }
        apiKey = getAPIKey(panLogin)
        baseURL = f"https://{panLogin['host']}"
        getCertURL = f"{baseURL}/api/?type=op&cmd=<request><certificate><show></show></certificate></request>&key={apiKey}"
        
        if apiKey:
            getCertRequest = requests.request("GET", getCertURL, verify=False)
            root = ET.fromstring(getCertRequest.text)
            for each in root.findall("./result/entry"):
                certificates.extend([{
                    'Device': dev['hostname'],
                    'Certificate': each.attrib['name'],
                    'Common Name': each.find('common-name').text,
                    'CA': each.find('ca').text,
                    'Validity': each.find('not-valid-after').text
                }])
            completed.append(dev['hostname'])
        else:
            failed.append(dev['hostname'])
        if certificates != 0:
            alert = []
            expired = []
            for cert in certificates:
                month = int(months[cert['Validity'].split()[0]])
                day = int(cert['Validity'].split()[1])
                year = int(cert['Validity'].split()[3])
                timedelta = datetime.date(year, month, day) - datetime.date.today()
                if int(timedelta.days) >= 0 and int(timedelta.days) < 90:
                    alert.extend([ cert ])
                elif int(timedelta.days) < 0:
                    expired.extend([ cert ])
    
            df_certs = pd.DataFrame(certificates)
            rows = int(len(df_certs.index.values)) + 1
            with pd.ExcelWriter(reportFile, engine='xlsxwriter') as writer:
                df_certs.to_excel(writer, sheet_name='certificates', index=False, )
                workbook = writer.book
                header_format = workbook.add_format({
                    'bold': True,
                    'italic': False,
                    'text_wrap': False,
                    'align': 'center',
                    'font_color': 'white',
                    'bg_color': Color((3,3)),
                    'border': 0
                })
                worksheet1 = writer.sheets['certificates']
                for col_num, value in enumerate(df_certs.columns.values):
                    worksheet1.write(0, col_num, value, header_format)
                    worksheet1.autofit()
                    worksheet1.autofilter(f"A1:E{str(rows)}")
                
                if len(alert) != 0:
                    df_alert = pd.DataFrame(alert)
                    df_alert.to_excel(writer, sheet_name='alert', index=False)
                    worksheet2 = writer.sheets['alert']
                    for col_num, value in enumerate(df_alert.columns.values):
                        worksheet2.write(0, col_num, value, header_format)
                        worksheet2.autofit()
                
                elif len(expired) != 0:
                    df_expired = pd.DataFrame(expired)
                    df_expired.to_excel(writer, sheet_name='expired', index=False)
                    worksheet3 = writer.sheets['alert']
                    for col_num, value in enumerate(df_expired.columns.values):
                        worksheet3.write(0, col_num, value, header_format)
                        worksheet3.autofit() 
    # log files
    with open (logFile, 'w') as f:
        f.write('Completed certificate validation on the below devices:\n------------------------------------------------------\n')
        f.write(('\n').join(completed))
        f.write('\n\nFailed certificate validation on the below devices:\n----------------------------------------------------\n')
        f.write(('\n').join(failed))
    print("Task completed!")

if __name__ == "__main__":
    runner()

