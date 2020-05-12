import requests
import sys
import json
import os
import time
import logging
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
        logger = get_logger("log/app_route_policy_changes.txt", log_level)
        
        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        app_route_policy_name = input("Please enter App aware route policy which needs to be replaced : ")
        latency = input("Latency for new App aware route policy (ms) (1-1000) : ")
        loss = input("Loss percentage for new App aware route policy (%) (1-100) : ")
        jitter = input("Jitter for new App aware route policy (ms) (1-1000) : ")

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,username,password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

        # Create new SLA class 

        payload = {
                    "name": app_route_policy_name+"_sla_class",
                    "description": app_route_policy_name+"_sla_class",
                    "type": "sla",
                    "entries": [
                        {
                        "latency": latency,
                        "loss": loss,
                        "jitter": jitter
                        }
                    ]
                  }


        api_url = "/template/policy/list/sla"

        url = base_url + api_url

        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            sla_class_id = response.json()["listId"]
            print("\nCreated new SLA Class %s_sla_class"%app_route_policy_name)
        else:
            print("\nFailed to create new SLA class")
            if logger is not None:
                logger.error("Failed to create new SLA class " + str(response.text))
            exit()


        # Get app aware route policies 

        api_url = "/template/policy/definition/approute"        

        url = base_url + api_url
        
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            app_aware_policy = response.json()["data"]
            for item in app_aware_policy:
                if item["name"] == app_route_policy_name:
                    old_app_aware_id = item["definitionId"]
                    break
            print("\nRetrieved app aware routing policies list")
        else:
            if logger is not None:
                logger.error("Failed to get app route policies list\n")
            exit()  

        # Get app aware route policy sequences definition 

        api_url = "/template/policy/definition/approute/%s"%old_app_aware_id

        url = base_url + api_url
        
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            temp = response.json()
            for item1 in temp["sequences"]:
                for item2 in item1["actions"]:
                    if item2['type'] == 'slaClass':
                        for item3 in item2['parameter']:
                            if item3["field"] == 'name':
                                item3["ref"] = sla_class_id

            app_policy_def = temp
            print("\nRetrieved app aware route policy definition %s"%app_route_policy_name)
        else:
            if logger is not None:
                logger.error("Failed to get app route policy sequences\n")
            exit()  


        # Create new App aware route policy

        payload = {
                    "name": "msuchand_" + app_policy_def["name"] ,
                    "type": app_policy_def["type"],
                    "description": "msuchand_" + app_policy_def["description"] ,
                    "sequences": app_policy_def["sequences"]
                    }

        if logger is not None:
            logger.info("App aware route policy post request payload :" + str(payload))

        api_url = '/template/policy/definition/approute' 

        url = base_url + api_url

        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            new_app_aware_id = response.json()["definitionId"]
            print("\nCreated app aware route policy msuchand_%s"%app_route_policy_name)
        else:
            if logger is not None:
                logger.error("Failed to create new App aware route policy\n" + str(response.text))
            exit()

        # Get current vSmart policies 

        api_url = "/template/policy/vsmart"

        url = base_url + api_url

        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            temp = response.json()["data"]
            for item in temp:
                if item["isPolicyActivated"] == True:
                    active_vsmart_policy_def = json.loads(item["policyDefinition"])
                    active_vsmart_policy_id = item["policyId"]
                    active_vsmart_policy_name = item["policyName"]
                    active_vsmart_policy_des = item["policyDescription"]
                    active_vsmart_policy_type = item["policyType"]
            
            # update app aware route policy id

            for item in active_vsmart_policy_def["assembly"]:
                if item["type"] == "appRoute" and item["definitionId"] == old_app_aware_id :
                    item["definitionId"] = new_app_aware_id
        else:
            if logger is not None:
                logger.error("Failed to get active vsmart policy, please check vsmart policy is defined\n")
            exit()

        # Put request to edit centralised policy

        payload = {
                    "policyDescription": active_vsmart_policy_des,
                    "policyType": active_vsmart_policy_type,
                    "policyName": active_vsmart_policy_name,
                    "policyDefinition": active_vsmart_policy_def,
                    "isPolicyActivated": True
                    }
        
        if logger is not None:
            logger.info("vsmart policy id " + active_vsmart_policy_id + "\n")
            logger.info("Edit vsmart policy put request payload :" + str(payload))

        api_url = '/template/policy/vsmart/%s'%active_vsmart_policy_id

        url = base_url + api_url

        response = requests.put(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
           vsmarts_device_id = response.json()
           print("\nUpdating vsmart policy with new app aware route policy")
        else:
            if logger is not None:
                logger.error("\nFailed to edit vsmart policy " + str(response.text))
            exit()

        # update vsmart policy with new app aware route policy 

        payload = { 
                    "isEdited":True
                  }

        api_url = "/template/policy/vsmart/activate/%s?confirm=true"%active_vsmart_policy_id

        url = base_url + api_url

        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
           process_id = response.json()["id"]
        else:
            if logger is not None:
                logger.error("\nFailed to edit vsmart policy " + str(response.text))
            exit()

        # Monitor vsmart policy push status   

        api_url = '/device/action/status/' + process_id  

        url = base_url + api_url

        while(1):
            time.sleep(10)
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                if response.json()['summary']['status'] == "done":
                    logger.info("\nvsmart policy push status is done")
                    print("\nUpdated vsmart policy with new app aware route policy")
                    break
                else:
                    continue
            else:
                if logger is not None:
                    logger.error("\nFetching policy push status failed " + str(response.text))
                exit()
            
        
        # Print updated vSmart policy

        api_url = "/template/policy/assembly/vsmart/%s"%active_vsmart_policy_id

        url = base_url + api_url

        response = requests.get(url=url,headers=headers, verify=False)

        if response.status_code == 200:
           policy_preview = response.json()["preview"]
           print("\n",policy_preview)
        else:
            if logger is not None:
                logger.error("\nFailed to get vsmart policy preview " + str(response.text))
            exit()

    except Exception as e:
        print('Failed due to error',str(e))
            