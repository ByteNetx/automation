#!/usr/bin/env python3
import argparse, getpass, os, json
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_napalm.plugins.tasks import napalm_get, napalm_cli, napalm_configure
from nornir.core.task import Task
import pandas as pd
from pathlib import Path
from xlsxwriter.color import Color

def run_tasks(task: Task):
    #task.run(
    #    task=napalm_cli, commands=['show version']
    #)
    task.run(
        task=napalm_get, getters=["facts"]
    )
    #task.run(
    #    task=napalm_configure,
    #    configuration= "interface loopback 1\ndescription 'configured by napalm'",
    #    replace=False
    #)

def main():
    class PASSWORD(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
                setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--u', help='Username', type=str,
    )
    parser.add_argument(
        '--p', help='Password', action=PASSWORD, nargs='?', dest='password', type=str, required=True
    )
    args = parser.parse_args()

    if args.u:
        username = args.u
    else:
        username = os.getlogin()

    basePath = Path.home() / 'nornir-env' / 'project'
    repFile = f"{basePath}/reports/nr_get_facts.xlsx"

    nr = InitNornir(
        config_file="config.yaml"
    )

    #nr = nr.filter(platform='nxos_ssh')
    nr.inventory.defaults.username = username
    nr.inventory.defaults.password = args.password

    try:
        results = nr.run(task=run_tasks)
    except Exception as e:
        print(f"An error occurred: {e}")
    else:
        data = []
        for host in results.keys():
            try:
                data.append({
                    'hostname': results[host][1].result['facts']['hostname'],
                    'os_version': results[host][1].result['facts']['os_version'],
                    'model': results[host][1].result['facts']['model'],
                    'serial_number': results[host][1].result['facts']['serial_number']
                })
            except ValueError as e:
                print(e)
    
        df = pd.DataFrame(data)
        writer = pd.ExcelWriter(repFile, engine="xlsxwriter")
        df.to_excel(writer, sheet_name="Inventory_UK", startrow=1, header=False)
        workbook = writer.book
        worksheet = writer.sheets["Inventory_UK"]
        header_format = workbook.add_format({
            'bold': True,
            'italic': False,
            'text_wrap': False,
            'align': 'center',
            'font_color': 'white',
            'bg_color': Color((3,3)),
            'border': 0
        })
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num + 1, value, header_format)
            worksheet.autofit()
        writer.close()

if __name__ == "__main__":
    main()
