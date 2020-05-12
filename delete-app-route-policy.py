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
        logger = get_logger("log/delete_app_route_policy.txt", log_level)
        
        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        app_route_policy_name = input("Please enter App aware route policy which was replaced : ") 

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
                elif item["name"] == "msuchand_" + app_route_policy_name:
                    new_app_aware_policy_id = item["definitionId"]

            print("\nRetrieved app aware route policy definition %s"%app_route_policy_name)            
        else:
            if logger is not None:
                logger.error("Failed to get app route policies list\n")
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
                if item["type"] == "appRoute" and item["definitionId"] == new_app_aware_policy_id:
                    item["definitionId"] = app_aware_policy_id

            print("\nRetrieved activated vsmart policy")

        else:
            if logger is not None:
                logger.error("Failed to get active vsmart policy, please check vsmart policy is defined\n")

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
                    print("\nUpdated vsmart policy with old app aware route policy")
                    break
                else:
                    continue
            else:
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

        # Delete app route policy

        api_url = "/template/policy/definition/approute/%s"%new_app_aware_policy_id

        url = base_url + api_url

        response = requests.delete(url=url,headers=headers, verify=False)

        if response.status_code == 200:
            if logger is not None:
                logger.error("\nDeleted msuchand_%s app route policy"%app_route_policy_name)
            print("\nDeleted msuchand_%s app route policy"%app_route_policy_name)
        else:
            if logger is not None:
                logger.error("\nFailed to delete msuchand_ app route policy " + str(response.text))
            exit()


        # Delete SLA class

        api_url = "/template/policy/list/sla"

        url = base_url + api_url

        response = requests.get(url=url,headers=headers, verify=False)

        if response.status_code == 200:
            temp = response.json()["data"]
            for item in temp:
                if item['name'] == app_route_policy_name+"_sla_class":
                    sla_class_id = item["listId"]
        else:
            if logger is not None:
                logger.error("\nFailed to get sla class list" + str(response.text))
            exit()

        api_url = "/template/policy/list/sla/%s"%sla_class_id

        url = base_url + api_url

        response = requests.delete(url=url,headers=headers, verify=False)

        if response.status_code == 200:
            if logger is not None:
                logger.error("\nDeleted %s_sla_class"%app_route_policy_name)
            print("\nDeleted %s_sla_class"%app_route_policy_name)
        else:
            if logger is not None:
                logger.error("\nFailed to delete %s_sla_class"%app_route_policy_name + str(response.text))
            exit()


    except Exception as e:
        print('Failed due to error',str(e))
            