import requests
import sys
import json
import os
import time
import logging
import tabulate
import yaml
import pandas as pd
from pandas import ExcelWriter
from logging.handlers import TimedRotatingFileHandler

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

def get_logger(logfile, level):
    '''
    Create a logger
    '''
    if logfile is not None:

        '''
        Create the log directory if it doesn't exist
        '''

        fldr = os.path.dirname(logfile)
        if not os.path.exists(fldr):
            os.makedirs(fldr)

        logger = logging.getLogger()
        logger.setLevel(level)
 
        log_format = '%(asctime)s | %(levelname)-8s | %(funcName)-20s | %(lineno)-3d | %(message)s'
        formatter = logging.Formatter(log_format)
 
        file_handler = TimedRotatingFileHandler(logfile, when='midnight', backupCount=7)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

        return logger

    return None


class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            if logger is not None:
                logger.error("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None

if __name__ == '__main__':

    try:

        log_level = logging.DEBUG
        logger = get_logger("log/app_route_report.txt", log_level)

        try: 
            start_date = input("Please enter start date(YYYY-MM-DD): ")
            time.strptime(start_date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect start data format, please enter in YYYY-MM-DD") 
        try:    
            end_date = input("Please enter end date(YYYY-MM-DD): ")
            time.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect end data format, please enter in YYYY-MM-DD")         

        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,username,password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

        # Get Device Inventory details 

        api_url = "/device"

        url = base_url + api_url

        response = requests.get(url=url, headers=headers, verify=False)

        device_inv = dict()

        if response.status_code == 200:
            temp = response.json()["data"]
            for item in temp:
                if item["personality"] == "vedge":
                    device_inv[item["system-ip"]] = [{'hostname' : item["host-name"]} , {'siteid' : item["site-id"]}]
        else:
            if logger is not None:
                logger.error("Failed to retrieve device inventory\n")

        # Get app route statistics for tunnels between Hub routers and Spoke routers.

        # open excel file 
        filename = 'Tunnel Statistics %s.xlsx'%time.strftime("%Y-%m-%d")
        writer = ExcelWriter(filename)

        for hub in config["hub_routers"]:

            api_url = "/statistics/approute/fec/aggregation"

            payload = {
                            "query": {
                                "condition": "AND",
                                "rules": [
                                {
                                    "value": [
                                              start_date+"T00:00:00 UTC",
                                              end_date+"T00:00:00 UTC" 
                                             ],
                                    "field": "entry_time",
                                    "type": "date",
                                    "operator": "between"
                                },
                                {
                                    "value": [
                                            hub["system_ip"]
                                            ],
                                    "field": "local_system_ip",
                                    "type": "string",
                                    "operator": "in"
                                }
                                ]
                            },
                            "aggregation": {
                                "field": [
                                {
                                    "property": "name",
                                    "sequence": 1
                                },
                                {
                                    "property": "proto",
                                    "sequence": 2
                                },
                                {
                                    "property": "local_system_ip",
                                    "sequence": 3
                                },
                                {
                                    "property": "remote_system_ip",
                                    "sequence": 4
                                }
                                ],
                                "histogram": {
                                "property": "entry_time",
                                "type": "hour",
                                "interval": 24,
                                "order": "asc"
                                },
                                "metrics": [
                                {
                                    "property": "latency",
                                    "type": "avg"
                                },
                                {
                                    "property": "jitter",
                                    "type": "avg"
                                },
                                {
                                    "property": "loss_percentage",
                                    "type": "avg"
                                },
                                {
                                    "property": "vqoe_score",
                                    "type": "avg"
                                }
                                ]
                            }
                            }

            url = base_url + api_url

            response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

            if response.status_code == 200:
                app_route_stats = response.json()["data"]
                app_route_stats_headers = ["Date", "Hub", "Hub Siteid", "Spoke", "Spoke Siteid", "Tunnel name", "vQoE score", "Latency", "Loss percentage", "Jitter"]
                table = list()

                date_list = list()
                hub_list = list()
                hub_siteid_list = list()
                spoke_list = list()
                spoke_siteid_list = list()
                tunnel_name_list = list()
                vqoe_list = list()
                latency_list = list()
                loss_list = list()
                jitter_list = list()

                print("\nAverage App route statistics between %s and spokes for %s and %s\n"%(device_inv[hub["system_ip"]][0]['hostname'],start_date,end_date))

                for item in app_route_stats:
                    tr = [time.strftime('%m/%d/%Y',  time.gmtime(item['entry_time']/1000.)), device_inv[item['local_system_ip']][0]['hostname'], device_inv[item['local_system_ip']][1]['siteid'], device_inv[item['remote_system_ip']][0]['hostname'], device_inv[item['remote_system_ip']][1]['siteid'], item['name'], item['vqoe_score'], item['latency'], item['loss_percentage'], item['jitter']]
                    table.append(tr)

                    date_list.append(time.strftime('%m/%d/%Y',  time.gmtime(item['entry_time']/1000.)))
                    hub_list.append(device_inv[item['local_system_ip']][0]['hostname'])
                    hub_siteid_list.append(device_inv[item['local_system_ip']][1]['siteid'])
                    spoke_list.append(device_inv[item['remote_system_ip']][0]['hostname'])
                    spoke_siteid_list.append(device_inv[item['remote_system_ip']][1]['siteid'])
                    tunnel_name_list.append(item['name'])
                    vqoe_list.append(item['vqoe_score'])
                    latency_list.append(item['latency'])
                    loss_list.append(item['loss_percentage'])
                    jitter_list.append(item['jitter'])

                try:
                    #print(tabulate.tabulate(table, app_route_stats_headers, tablefmt="fancy_grid"))
                    excel_content = dict()
                    excel_content["Date"] = date_list
                    excel_content["Hub"] = hub_list
                    excel_content["Hub Siteid"] = hub_siteid_list
                    excel_content["Spoke"] = spoke_list
                    excel_content["Spoke Siteid"] = spoke_siteid_list
                    excel_content["Tunnel name"] = tunnel_name_list
                    excel_content["vQoE score"] = vqoe_list
                    excel_content["Latency"] = latency_list
                    excel_content["Loss percentage"] = loss_list
                    excel_content["Jitter"] = jitter_list

                    df = pd.DataFrame(excel_content)
                    df.to_excel(writer, device_inv[hub["system_ip"]][0]['hostname'] ,index=False)
                    
                except UnicodeEncodeError:
                    print(tabulate.tabulate(table, app_route_stats_headers, tablefmt="grid"))
                
            else:
                if logger is not None:
                    logger.error("Failed to retrieve app route statistics\n")

        writer.save()
        print("\nCreated report %s"%filename)

    except Exception as e:
        print('Exception line number: {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            