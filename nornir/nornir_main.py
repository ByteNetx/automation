#!/usr/bin/env python3
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_napalm.plugins.tasks import napalm_get, napalm_cli, napalm_configure
from nornir.core.task import Task
import pandas as pd
import json

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
        df.to_excel(excel_file, index=False, engine='xlsxwriter')
