import requests
import sys
import json
import os
import time
import logging
import tabulate
import yaml
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

        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        rtr1_systemip = input("Enter Router-1 System IP address : ")
        rtr2_systemip = input("Enter Router-2 System IP address : ")

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,username,password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

        # Get app route statistics for tunnels between router-1(rtr1_systemip) and router-2(rtr2_systemip)

        api_url = "/statistics/approute/fec/aggregation"

        payload = {
                        "query": {
                            "condition": "AND",
                            "rules": [
                            {
                                "value": [
                                "2020-02-29T08:00:00 UTC",
                                "2020-03-31T07:00:00 UTC"
                                ],
                                "field": "entry_time",
                                "type": "date",
                                "operator": "between"
                            },
                            {
                                "value": [
                                          rtr1_systemip
                                         ],
                                "field": "local_system_ip",
                                "type": "string",
                                "operator": "in"
                            },
                            {
                                "value": [
                                         rtr2_systemip
                                        ],
                                "field": "remote_system_ip",
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
            app_route_stats_headers = ["Date", "Tunnel name", "vQoE score", "Latency", "Loss percentage", "Jitter"]
            table = list()

            print("\nAverage App route statistics between %s and %s for last 30 days\n"%(rtr1_systemip,rtr2_systemip))
            for item in app_route_stats:
                tr = [time.strftime('%m/%d/%Y',  time.gmtime(item['entry_time']/1000.)), item['name'], item['vqoe_score'], item['latency'], item['loss_percentage'], item['jitter']]
                table.append(tr)
            try:
                print(tabulate.tabulate(table, app_route_stats_headers, tablefmt="fancy_grid"))
                csv_content = tabulate.tabulate(table, app_route_stats_headers, tablefmt="csv")
                file_name   = open("Tunnel Statistics %s.csv"%time.strftime("%Y-%m-%d"),"w")
                file_name.write(csv_content)
                file_name.close()
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, app_route_stats_headers, tablefmt="grid"))
            
        else:
            if logger is not None:
                logger.error("Failed to retrieve app route statistics\n")

    except Exception as e:
        print('Failed due to error',str(e))
            