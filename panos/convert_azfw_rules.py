import pandas as pd
from pathlib import Path
import json, os, sys
from xlsxwriter.color import Color
from xlsxwriter.utility import xl_col_to_name

basePath = Path.home() / 'pyenv3.13' / 'panos' 
inFile = "config_data/AzureFirewallERAllPolicies.json"
reportFile = "config_data/azfw_rules.xlsx"

if os.path.exists(inFile):
    with open(inFile, encoding="utf-8-sig") as f:
        data = json.load(f)
else:
    sys.exit(0)

rules = []
for item in data['resources']:
    if "ruleCollectionGroups" in item['type']:
        grpName = item['name'].split("/")[1].strip("')]")
        grpPriority = item['properties']['priority']
        for entry in item['properties']['ruleCollections']:
            collectionName = entry['name']
            collectionPriority = entry['priority']
            action = entry['action']['type']
            for each in entry['rules']:
                rule = {k: v for k,v in each.items() if v}
                protocols = []
                if 'protocols' in rule.keys():
                    if isinstance(rule['protocols'], list) and len(rule['protocols']) != 0:
                        for prot in rule['protocols']:
                            protocols.append(f"{prot['protocolType']}-{prot['port']}")
                        rule['protocols'] = protocols
                rule.update({
                    "action": action,
                    "groupName": grpName,
                    "groupPriority": grpPriority,
                    "collectionName": collectionName,
                    "collectionPriority": collectionPriority
                })
                if rule['ruleType'] == 'NetworkRule' and 'destinationPorts' in rule.keys():
                    services = [v for k, v in rule.items() if k == 'destinationPorts']
                    services = [item for sublist in services for item in sublist]
                    rule['destinationPorts'] = services
                rules.append(rule)

new_rules = []
for each in rules:
    new_rules.append({k: ",".join(map(str, v)) if isinstance(v, list) else v for k, v in each.items()})

sorted_rules = sorted(new_rules, key=lambda x: (x['groupPriority'], x['collectionPriority']))

df_rules = pd.DataFrame(sorted_rules)
df_rules.fillna('',inplace=True)
rows = df_rules.shape[0]
columes = xl_col_to_name(df_rules.shape[1])
headers = df_rules.columns.tolist()
with pd.ExcelWriter(reportFile, engine='xlsxwriter') as writer:
    df_rules.to_excel(writer, sheet_name='azfw_rules', index=False, )
    workbook = writer.book
    header_format = workbook.add_format({
        'bold': True,
        'italic': False,
        'text_wrap': False,
        'align': 'center',
        'font_color': 'white',
        'bg_color': Color((3,3)),
        'border': 0,
    })
    worksheet1 = writer.sheets['azfw_rules']
    for col_num, value in enumerate(headers):
        worksheet1.write(0, col_num, value, header_format)
    worksheet1.autofit()
    worksheet1.autofilter(f"A1:{columes}{str(rows)}")
