import requests
import sys
import json
import time
import logging
import yaml
import os
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


def get_device_ids(jsessionid,token,template_id):

    if token is not None:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid}

    base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

    api_url = '/template/device/config/attached/' + template_id

    url = base_url + api_url

    response = requests.get(url=url, headers=headers,verify=False)

    if response.status_code == 200:
        device_ids = []
        for device in response.json()['data']:
            device_ids.append(device['uuid'])
        if logger is not None:
            logger.info("Device ids " + str(device_ids))
        return device_ids
    else:
        if logger is not None:
            logger.error("Failed to get device ids " + str(response.text))
        exit()

def get_device_inputs(jsessionid,token,template_id, device_ids):

    if token is not None:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid}

    payload = {
        'templateId': template_id,
        'deviceIds': device_ids,
        'isEdited': True,
        'isMasterEdited': False
    }

    base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

    api_url = '/template/device/config/input'

    url = base_url + api_url    

    response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

    if response.status_code == 200:

        device_inputs = response.json()['data']

        for input in device_inputs:
            input['csv-templateId'] = template_id
    
        if logger is not None:
            logger.info("Device config input" + str(device_inputs))
    else:
        if logger is not None:
            logger.error("Failed to get device config input " + str(response.text))
        exit()

    return device_inputs

if __name__ == '__main__':

    try:

        log_level = logging.DEBUG
        logger = get_logger("log/app_route_change_logs.txt", log_level)
        
        new_path = input("Please enter new transport color ")
        app_route_policy_name = input("Please enter app route policy name(in which transport color has to be modified) ")     

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

        # Get app aware route policies 

        api_url = "/template/policy/definition/approute"        

        url = base_url + api_url
        
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            app_aware_policy = response.json()["data"]
            for item in app_aware_policy:
                if item["name"] == app_route_policy_name:
                    app_aware_policy_id = item["definitionId"]
                    break     
        else:
            if logger is not None:
                logger.error("Failed to get app route policies list\n")
            exit()  

        # Get app aware route policy sequences definition 

        api_url = "/template/policy/definition/approute/%s"%app_aware_policy_id

        url = base_url + api_url
        
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            temp = response.json()
            for item1 in temp["sequences"]:
                for item2 in item1["actions"]:
                    if item2['type'] == 'slaClass':
                        for item3 in item2['parameter']:
                            if item3["field"] == 'preferredColor':
                                item3["value"] = new_path

            app_policy_def = temp
            print("\nRetrieved app aware route policy definition for %s"%app_route_policy_name)
        else:
            if logger is not None:
                logger.error("Failed to get app route policy sequences\n")
            exit() 

        # Update policy app route policy 

        payload = {
                    "name": app_policy_def["name"] ,
                    "type": app_policy_def["type"],
                    "description": app_policy_def["description"] ,
                    "sequences": app_policy_def["sequences"]
                  }

        response = requests.put(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            master_templates_affected = response.json()['masterTemplatesAffected']
            if logger is not None:
                logger.info("Master templates affected " + str(master_templates_affected))
        else:
            if logger is not None:
                logger.error("\nFailed to edit app route policy " + str(response.text))
            exit()

        # Get device uuid and csv variables for each template id which is affected by prefix list edit operation

        inputs = []

        for template_id in master_templates_affected:
            device_ids = get_device_ids(jsessionid,token,template_id)
            device_inputs = get_device_inputs(jsessionid,token,template_id,device_ids)
            inputs.append((template_id, device_inputs))


        device_template_list = []
        
        for (template_id, device_input) in inputs:
            device_template_list.append({
                'templateId': template_id,
                'isEdited': True,
                'device': device_input
            })


        #api_url for CLI template 'template/device/config/attachcli'

        api_url = '/template/device/config/attachfeature'

        url = base_url + api_url

        payload = { 'deviceTemplateList': device_template_list }

        response = requests.post(url=url, headers=headers,  data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            process_id = response.json()["id"]
            if logger is not None:
                logger.info("Attach template process id " + str(response.text))
        else:
            if logger is not None:
                logger.error("Template attach process failed " + str(response.text))     

        api_url = '/device/action/status/' + process_id  

        url = base_url + api_url

        while(1):
            time.sleep(10)
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                if response.json()['summary']['status'] == "done":
                    logger.info("\nTemplate push status is done")
                    print("Updated App route policy successfully")
                    break
                else:
                    continue
            else:
                logger.error("\nFetching template push status failed " + str(response.text))
                exit()
            

    except Exception as e:
        print('Exception line number: {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            