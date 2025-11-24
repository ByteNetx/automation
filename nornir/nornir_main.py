#!/usr/bin/env python3
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_napalm.plugins.tasks import napalm_get, napalm_cli, napalm_configure
from nornir.core.task import Task
import pandas as pd
import json
from xlsxwriter.color import Color

nr = InitNornir(
    config_file="config.yaml"
)

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

try:
    results = nr.run(
        task=run_tasks
    )
except Exception as e:
    print(f"An error occurred: {e}")
else:
    data = []
    try:
        for host in results.keys():
            data.append({
                'hostname': results[host][1].result['facts']['hostname'],
                'os_version': results[host][1].result['facts']['os_version'],
                'model': results[host][1].result['facts']['model'],
                'serial_number': results[host][1].result['facts']['serial_number']
            })
            print(json.dumps(data, indent=2))
        df = pd.DataFrame(data)
    except ValueError as e:
        print(e)
    else:
        excel_file = "napalm_facts.xlsx"
        writer = pd.ExcelWriter(excel_file, engine="xlsxwriter")
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
