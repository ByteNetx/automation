import argparse, csv, sys
import pandas as pd
from xlsxwriter import Workbook
from xlsxwriter.color import Color
from operator import itemgetter, attrgetter
from pathlib import Path

def banner():
    print("""
****************************************************
* The script analyzes the PA NGFW traffic logs and *
* generates an Excel report file in the following  *
* location:                                        *
*   ~/pyenv3.9/panos/reports                       *
****************************************************
    """)

def runner():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--f', help='Traffic log csv file', required=True
    )
    parser.add_argument(
        '--sort', help='Sort key', choices=['app', 'src', 'dest'], default='src'
    )
    args = parser.parse_args()

    inFile = args.f
    basePath = Path.home() / 'pyenv3.9' / 'panos'
    trafficLog = f"{basePath}/traffic_logs/{inFile}"
    outFile = inFile.replace('log_','report_').replace(".csv", ".xlsx")
    reportFile = f"{basePath}/traffic_reports/{outFile}"

    flows = []
    blocked_flows = []
    incomplete_flows = []

    print('Analyze traffic logs...')
    try:
        df = pd.read_csv(
            trafficLog,
            header=0,
            low_memory=False,
            usecols=[
                'Source address',
                'Destination address',
                'Source Zone',
                'Inbound Interface',
                'Destination Zone',
                'Outbound Interface',
                'Source User',
                'Application',
                'IP Protocol',
                'Source Port',
                'Destination Port',
                'Bytes Received',
                'Bytes Sent',
                'Action',
                'Rule',
                'Device Name'
            ]
        )
        df.fillna('',inplace=True)
    except FileNotFoundError as error:
        sys.exit(error)
    for i in df.index:
        if df.loc[i]['Action'] != 'allow':
            blocked_flows.extend([(
                df.loc[i]['Source Zone'],
                df.loc[i]['Inbound Interface'],
                df.loc[i]['Source address'],
                df.loc[i]['Source User'],
                df.loc[i]['Destination Zone'],
                df.loc[i]['Outbound Interface'],
                df.loc[i]['Destination address'],
                df.loc[i]['Application'],
                df.loc[i]['IP Protocol'],
                df.loc[i]['Destination Port'],
                df.loc[i]['Rule'],
                df.loc[i]['Device Name']
            )])
        elif df.loc[i]['Application'] == 'incomplete':
            incomplete_flows.extend([(
                df.loc[i]['Source Zone'],
                df.loc[i]['Inbound Interface'],
                df.loc[i]['Source address'],
                df.loc[i]['Source User'],
                df.loc[i]['Destination Zone'],
                df.loc[i]['Outbound Interface'],
                df.loc[i]['Destination address'],
                df.loc[i]['Application'],
                df.loc[i]['IP Protocol'],
                df.loc[i]['Destination Port'],
                df.loc[i]['Bytes Received'],
                df.loc[i]['Bytes Sent'],
                df.loc[i]['Rule'],
                df.loc[i]['Device Name']
            )])
        else:
            flows.extend([(
                df.loc[i]['Source Zone'],
                df.loc[i]['Inbound Interface'],
                df.loc[i]['Source address'],
                df.loc[i]['Source User'],
                df.loc[i]['Destination Zone'],
                df.loc[i]['Outbound Interface'],
                df.loc[i]['Destination address'],
                df.loc[i]['Application'],
                df.loc[i]['IP Protocol'],
                df.loc[i]['Destination Port'],
                df.loc[i]['Rule'],
                df.loc[i]['Device Name']
            )])
    # Remove duplicate and sort flows, IPs, and applications
    if args.sort == 'src':
        flows = sorted(set(flows), key=itemgetter(2,6,7))
        blocked_flows = sorted(set(blocked_flows), key=itemgetter(2,6,7))
    elif args.sort == 'dest':
        flows = sorted(set(flows), key=itemgetter(6,2,7))
        blocked_flows = sorted(set(blocked_flows), key=itemgetter(6,2,7))
    elif args.sort == 'app':
        flows = sorted(set(flows), key=itemgetter(7,2,6))
        blocked_flows = sorted(set(blocked_flows), key=itemgetter(7,2,6))
    incomplete_flows = sorted(set(incomplete_flows))
    applications = list(sorted(set([app for (src_zone, in_intf, src_ip, src_user, dest_zone, out_intf, dest_ip, app, protocol, service, rule, device_name) in flows])))
    
    flow_header = [
        'From',
        'Ingress Interface',
        'Source IP',
        'Source User',
        'To',
        'Egress Interface',
        'Destination IP',
        'Application',
        'IP Protocol',
        'Destination Port',
        'Rule',
        'Device Name'
    ]

    incomplete_header = [
        'From',
        'Ingress Interface',
        'Source IP',
        'Source User',
        'To',
        'Egress Interface',
        'Destination IP',
        'Application',
        'IP Protocol',
        'Destination Port',
        'Bytes Received',
        'Bytes Sent',
        'Rule',
        'Device Name'
    ]

    df_flows = pd.DataFrame(flows)
    rows = int(len(df_flows.index.values)) + 1
    with pd.ExcelWriter(reportFile, engine='xlsxwriter') as writer:
        df_flows.to_excel(writer, sheet_name='flows', index=False, )
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
        worksheet1 = writer.sheets['flows']
        for col_num, value in enumerate(flow_header):
            worksheet1.write(0, col_num, value, header_format)
        worksheet1.autofit()
        worksheet1.autofilter(f"A1:L{str(rows)}")

        if len(incomplete_flows) != 0:
            df_incomplete = pd.DataFrame(incomplete_flows)
            df_incomplete.to_excel(writer, sheet_name='incomplete', index=False, )
            worksheet2 = writer.sheets['incomplete']
            for col_num, value in enumerate(incomplete_header):
                worksheet2.write(0, col_num, value, header_format)
            worksheet2.autofit()
        if len(blocked_flows) != 0:
            df_blocked = pd.DataFrame(blocked_flows)
            df_blocked.to_excel(writer, sheet_name='blocked', index=False, )
            worksheet3 = writer.sheets['blocked']
            for col_num, value in enumerate(flow_header):
                worksheet3.write(0, col_num, value, header_format)
            worksheet3.autofit()
        df_app = pd.DataFrame(applications)
        df_app.to_excel(writer, sheet_name='applications', index=False, header=False )
        worksheet4 = writer.sheets['applications']
        worksheet4.autofit()

    print('Task Completed!')

if __name__ == "__main__":
    runner()
