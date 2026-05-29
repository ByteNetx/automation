import time, json
import requests, argparse, getpass, json
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
from openpyxl.workbook import Workbook
from xlsxwriter.color import Color
from get_access_token import get_access_token
from encryption import decrypt

baseURL = "https://api.strata.paloaltonetworks.com/config"
TSG_ID = "tsg_id:xxxxxxx"
CLIENT_ID = "xxxxxxxxxxx"
credFile = Path.home() / 'pyenv3.9' / 'secrets' / 'panos_secrets.bin'

def get_scm_data(path: str, token: str, offset: int = 0, limit: int = 200, **scope) -> List[Dict[str, Any]]:

    all_items = []

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    print(scope)

    while True:
        # Prepare parameters: Combine pagination with user-provided scope filters
        params = {
            "limit": limit,
            "offset": offset,
            scope['scope'].split('=')[0]: scope['scope'].split('=')[1]
        }

        print(f"\nFetching items {offset} to {offset + limit}...")

        try:
            # Execute the GET request
            response = requests.get(path, headers=headers, params=params)

            # This will raise an error for 4xx or 5xx responses
            response.raise_for_status()

            data = response.json()
            items = data.get("data", [])

            # No more data to fetch
            if not items:
                break

            all_items.extend(items)

            # If the number of items returned is less than the limit, we have
            # reached the end of the data set (last page).
            if len(items) < limit:
                break

            # Increment the offset for the next API call
            offset += limit

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            break

    print(f"\nRetrieved {len(all_items)} total objects.")
    return all_items

def runner():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--s', help='Scope, Example: "folder=Mobile Users"', type=str, required=True, default="All"
    )
    parser.add_argument(
        '--config', help='The YAML file of PA NGFW Configurations', type=str
    )
    args = parser.parse_args()
    credentials = decrypt(credFile)
    srvAccount={
        "client_id": CLIENT_ID,
        "client_credential": credentials[CLIENT_ID]
    }
    basePath = Path.home() / 'pyenv3.9' / 'panos'
    SCOPE = args.s
    q_scope = SCOPE.split('=')[1]
    reportFile = f"{basePath}/reports/prisma_config_{q_scope}.xlsx"
    TOKEN = get_access_token(TSG_ID, srvAccount)

    rules = get_scm_data(f"{baseURL}/security/v1/security-rules", token=TOKEN, scope=SCOPE)
    profileGroups = get_scm_data(f"{baseURL}/security/v1/profile-groups", token=TOKEN, scope=SCOPE)
    
    with open(f"{basePath}/reports/prisma_rules.json", "w", encoding='utf-8-sig') as f:
        json.dump(rules, f, indent=2)
    with open(f"{basePath}/reports/prisma_pgs.json", "w", encoding='utf-8-sig') as f:
        json.dump(profileGroups, f, indent=2)

    #df_rules = pd.DataFrame(rules)
    #rules_rows = int(len(df_rules.index.values)) + 1
    #df_profileGroups = pd.DataFrame(profileGroups)
    #profileGroups_rows = int(len(df_profileGroups.index.values)) + 1

    #with pd.ExcelWriter(reportFile, engine='xlsxwriter') as writer:
    #    df_rules.to_excel(writer, sheet_name='security rules', index=False, )
    #    workbook = writer.book
    #    header_format = workbook.add_format({
    #        'bold': True,
    #        'italic': False,
    #        'text_wrap': False,
    #        'align': 'center',
    #        'font_color': 'white',
    #        'bg_color': Color((3,3)),
    #        'border': 0
    #    })
    #    worksheet1 = writer.sheets['security rules']
    #    for col_num, value in enumerate(df_rules.columns.values):
    #       worksheet1.write(0, col_num, value, header_format)
    #        worksheet1.autofit()
    #        worksheet1.autofilter(f"A1:E{str(rules_rows)}")

    #    df_profileGroups.to_excel(writer, sheet_name='profile groups', index=False, )
    #    workbook = writer.book
    #    header_format = workbook.add_format({
    #        'bold': True,
    #        'italic': False,
    #        'text_wrap': False,
    #        'align': 'center',
    #        'font_color': 'white',
    #        'bg_color': Color((3,3)),
    #        'border': 0
    #    })
    #    worksheet2 = writer.sheets['profile groups']
    #    for col_num, value in enumerate(df_profileGroups.columns.values):
    #        worksheet2.write(0, col_num, value, header_format)
    #        worksheet2.autofit()
    #        worksheet2.autofilter(f"A1:E{str(profileGroups_rows)}")


if __name__ == "__main__":
    runner()
