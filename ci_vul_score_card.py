from lib import al_ci_client
from datetime import datetime
import requests
import logging
import json
import copy
import argparse
import sys
from copy import deepcopy
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

def collect_total_host_scanned(args):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_scheduler_summary()
    if myEnv:
        return myEnv["summary"]
    else:
        return False

def temp_count_host_with_aws_config_vul(args):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()

    if myEnv:
        #ALL VULNERABILITY RELATED TO HOST (AWS CONFIG + APP LEVEL)
        query_args = {}
        query_args["asset_types"] = "h:host,v:vulnerability"
        query_args["v.severity"] = "$VAR"
        query_args["VAR.type"] = "string[]"
        query_args["VAR.value"] = "info,low,medium,high"
        query_args["VAR.comparison"] = "member_of"
        query_args["query_format"] = "v2"
        host_all_vulnerability = myCI.get_asset_custom(query_args)

        #ALL APP LEVEL VULNERABILITY RELATED TO HOST
        query_args = {}
        query_args["asset_types"] = "h:host,v:vulnerability"
        query_args["v.scope_scan_severity"] = "$VAR"
        query_args["VAR.type"] = "string[]"
        query_args["VAR.value"] = "Info,Low,Medium,High"
        query_args["VAR.comparison"] = "member_of"
        query_args["query_format"] = "v2"
        host_app_vulnerability = myCI.get_asset_custom(query_args)

        result = int(host_all_vulnerability["rows"]) - int(host_app_vulnerability["rows"])
        return result
    else:
        return 0

def collect_host_that_vulnerable(args):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()

    if myEnv:
        query_args = {}
        query_args["asset_types"] = "h:host,v:vulnerability"
        query_args["v.severity"] = "$VAR"
        query_args["VAR.type"] = "string[]"
        query_args["VAR.value"] = "info,low,medium,high"
        query_args["VAR.comparison"] = "member_of"
        query_args["query_format"] = "v2"
        host_that_vulnerable = myCI.get_asset_custom(query_args)

        host_that_vulnerable_high = []
        host_that_vulnerable_medium = []
        host_that_vulnerable_low = []
        host_that_vulnerable_info = []
        host_that_vulnerable_total = []
        host_that_vulnerable_high_or_medium = []

        for host in host_that_vulnerable["assets"]:
            if host[1]["severity"] == "high":
                host_that_vulnerable_high.append(host[0]["instance_id"])
                host_that_vulnerable_high_or_medium.append(host[0]["instance_id"])
            elif host[1]["severity"] == "medium":
                host_that_vulnerable_medium.append(host[0]["instance_id"])
                host_that_vulnerable_high_or_medium.append(host[0]["instance_id"])
            elif host[1]["severity"] == "low":
                host_that_vulnerable_low.append(host[0]["instance_id"])
            elif host[1]["severity"] == "info":
                host_that_vulnerable_info.append(host[0]["instance_id"])
            host_that_vulnerable_total.append(host[0]["instance_id"])

        result = {}
        result["total"] = len(set(host_that_vulnerable_total))
        result["high"] = len(set(host_that_vulnerable_high))
        result["medium"] = len(set(host_that_vulnerable_medium))
        result["low"] = len(set(host_that_vulnerable_low))
        result["info"] = len(set(host_that_vulnerable_info))
        result["high_medium"] = len(set(host_that_vulnerable_high_or_medium))

        logger.info("CID: {0} - EnvId: {1} - Total Unique Host with vulnerabilities: {2}".format(myEnv["account_id"], myEnv["id"], result["total"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host with vulnerability High: {2}".format(myEnv["account_id"], myEnv["id"], result["high"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host with vulnerability Medium: {2}".format(myEnv["account_id"], myEnv["id"], result["medium"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host with vulnerability Low: {2}".format(myEnv["account_id"], myEnv["id"], result["low"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host with vulnerability Info: {2}".format(myEnv["account_id"], myEnv["id"], result["info"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host with vulnerability High & Medium: {2}".format(myEnv["account_id"], myEnv["id"], result["high_medium"]))

        return result
    else:
        return False

def collect_vulnerability(args):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()
    if myEnv:
        query_args = {}
        query_args["asset_types"] = "vulnerability"
        vulnerabilities = myCI.get_asset_custom(query_args)
        host_vulnerability_count = {}
        host_vulnerability_count["high"] = 0
        host_vulnerability_count["medium"] = 0
        host_vulnerability_count["low"] = 0
        host_vulnerability_count["info"] = 0
        non_host_vulnerability_count = {}
        non_host_vulnerability_count["high"] = 0
        non_host_vulnerability_count["medium"] = 0
        non_host_vulnerability_count["low"] = 0
        non_host_vulnerability_count["info"] = 0

        for vulnerability in vulnerabilities["assets"]:
            if "scope_scan_ip_address" in vulnerability[0]:
                vulnerability_type = "host"
            else:
                vulnerability_type = "non-host"

            if vulnerability[0]["severity"] == "high":
                if vulnerability_type == "host":
                    host_vulnerability_count["high"] = host_vulnerability_count["high"] + 1
                else:
                    non_host_vulnerability_count["high"] = non_host_vulnerability_count["high"] + 1

            elif vulnerability[0]["severity"] == "medium":
                if vulnerability_type == "host":
                    host_vulnerability_count["medium"] = host_vulnerability_count["medium"] + 1
                else:
                    non_host_vulnerability_count["medium"] = non_host_vulnerability_count["medium"] + 1

            elif vulnerability[0]["severity"] == "low":
                if vulnerability_type == "host":
                    host_vulnerability_count["low"] = host_vulnerability_count["low"] + 1
                else:
                    non_host_vulnerability_count["low"] = non_host_vulnerability_count["low"] + 1

            elif vulnerability[0]["severity"] == "info":
                if vulnerability_type == "host":
                    host_vulnerability_count["info"] = host_vulnerability_count["info"] + 1
                else:
                    non_host_vulnerability_count["info"] = non_host_vulnerability_count["info"] + 1

        logger.info("CID: {0} - EnvId: {1} - Total vulnerabilities: {2}".format(myEnv["account_id"], myEnv["id"], vulnerabilities["rows"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host vulnerability High: {2}".format(myEnv["account_id"], myEnv["id"], host_vulnerability_count["high"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host vulnerability Medium: {2}".format(myEnv["account_id"], myEnv["id"], host_vulnerability_count["medium"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host vulnerability Low: {2}".format(myEnv["account_id"], myEnv["id"], host_vulnerability_count["low"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Host vulnerability Info: {2}".format(myEnv["account_id"], myEnv["id"], host_vulnerability_count["info"]))

        logger.info("|- CID: {0} - EnvId: {1} - Total Non Host vulnerability High: {2}".format(myEnv["account_id"], myEnv["id"], non_host_vulnerability_count["high"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Non Host vulnerability Medium: {2}".format(myEnv["account_id"], myEnv["id"], non_host_vulnerability_count["medium"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Non Host vulnerability Low: {2}".format(myEnv["account_id"], myEnv["id"], non_host_vulnerability_count["low"]))
        logger.info("|- CID: {0} - EnvId: {1} - Total Non Host vulnerability Info: {2}".format(myEnv["account_id"], myEnv["id"], non_host_vulnerability_count["info"]))

    return host_vulnerability_count, non_host_vulnerability_count

def ci_get_env_cid(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args={}
    query_args['type'] = 'aws'
    query_args['defender_support'] = 'false'
    return myCI.get_environments_by_cid_custom(query_args)

def monitor_per_cid(args):
    logger.info("### Start Operations : {0} - API Query Env ID for CID: {1}".format(datetime.now(), args["acc_id"]))
    ci_environments = ci_get_env_cid(args)
    logger.info("### Finish Operations : {0} - Env ID found: {1}".format(datetime.now(), ci_environments["count"]))

    if ci_environments:
        per_cid_total_host_vulnerability = {}
        per_cid_total_host_vulnerability["high"] = 0
        per_cid_total_host_vulnerability["medium"] = 0
        per_cid_total_host_vulnerability["low"] = 0
        per_cid_total_host_vulnerability["info"] = 0

        per_cid_total_non_host_vulnerability = {}
        per_cid_total_non_host_vulnerability["high"] = 0
        per_cid_total_non_host_vulnerability["medium"] = 0
        per_cid_total_non_host_vulnerability["low"] = 0
        per_cid_total_non_host_vulnerability["info"] = 0

        per_cid_total_host_with_vulnerability = {}
        per_cid_total_host_with_vulnerability["total"] = 0
        per_cid_total_host_with_vulnerability["high"] = 0
        per_cid_total_host_with_vulnerability["medium"] = 0
        per_cid_total_host_with_vulnerability["low"] = 0
        per_cid_total_host_with_vulnerability["info"] = 0
        per_cid_total_host_with_vulnerability["high_medium"] = 0

        per_cid_total_host = {}
        per_cid_total_host["scanned"] = 0
        per_cid_total_host["total"] = 0

        for env in ci_environments["environments"]:
            args["env_id"] = env["id"]
            host_vulnerability_count, non_host_vulnerability_count = collect_vulnerability(args)
            per_cid_total_host_vulnerability["high"] = per_cid_total_host_vulnerability["high"] + host_vulnerability_count["high"]
            per_cid_total_host_vulnerability["medium"] = per_cid_total_host_vulnerability["medium"] + host_vulnerability_count["medium"]
            per_cid_total_host_vulnerability["low"] = per_cid_total_host_vulnerability["low"] + host_vulnerability_count["low"]
            per_cid_total_host_vulnerability["info"] = per_cid_total_host_vulnerability["info"] + host_vulnerability_count["info"]

            per_cid_total_non_host_vulnerability["high"] = per_cid_total_non_host_vulnerability["high"] + non_host_vulnerability_count["high"]
            per_cid_total_non_host_vulnerability["medium"] = per_cid_total_non_host_vulnerability["medium"] + non_host_vulnerability_count["medium"]
            per_cid_total_non_host_vulnerability["low"] = per_cid_total_non_host_vulnerability["low"] + non_host_vulnerability_count["low"]
            per_cid_total_non_host_vulnerability["info"] = per_cid_total_non_host_vulnerability["info"] + non_host_vulnerability_count["info"]

            host_that_vulnerable = collect_host_that_vulnerable(args)
            per_cid_total_host_with_vulnerability["total"] = per_cid_total_host_with_vulnerability["total"] + host_that_vulnerable["total"]
            per_cid_total_host_with_vulnerability["high"] = per_cid_total_host_with_vulnerability["high"] + host_that_vulnerable["high"]
            per_cid_total_host_with_vulnerability["medium"] = per_cid_total_host_with_vulnerability["medium"] + host_that_vulnerable["medium"]
            per_cid_total_host_with_vulnerability["low"] = per_cid_total_host_with_vulnerability["low"] + host_that_vulnerable["low"]
            per_cid_total_host_with_vulnerability["info"] = per_cid_total_host_with_vulnerability["info"] + host_that_vulnerable["info"]
            per_cid_total_host_with_vulnerability["high_medium"] = per_cid_total_host_with_vulnerability["high_medium"] + host_that_vulnerable["high_medium"]

            scheduler_summary = collect_total_host_scanned(args)
            per_cid_total_host["scanned"] = per_cid_total_host["scanned"] + scheduler_summary["scanned"] + temp_count_host_with_aws_config_vul(args)
            per_cid_total_host["total"] = per_cid_total_host["total"] + scheduler_summary["total"]


    logger.info("### Sub Total for CID {0}".format(args["acc_id"]))
    logger.info("|- CID: {0} - Sub Total Host vulnerability High: {1} ".format(args["acc_id"], per_cid_total_host_vulnerability["high"]))
    logger.info("|- CID: {0} - Sub Total Host vulnerability Medium: {1} ".format(args["acc_id"], per_cid_total_host_vulnerability["medium"]))
    logger.info("|- CID: {0} - Sub Total Host vulnerability Low: {1} ".format(args["acc_id"], per_cid_total_host_vulnerability["low"]))
    logger.info("|- CID: {0} - Sub Total Host vulnerability Info: {1} ".format(args["acc_id"], per_cid_total_host_vulnerability["info"]))
    logger.info("|- CID: {0} - Sub Total Non Host vulnerability High: {1} ".format(args["acc_id"], per_cid_total_non_host_vulnerability["high"]))
    logger.info("|- CID: {0} - Sub Total Non Host vulnerability Medium: {1} ".format(args["acc_id"], per_cid_total_non_host_vulnerability["medium"]))
    logger.info("|- CID: {0} - Sub Total Non Host vulnerability Low: {1} ".format(args["acc_id"], per_cid_total_non_host_vulnerability["low"]))
    logger.info("|- CID: {0} - Sub Total Non Host vulnerability Info: {1} ".format(args["acc_id"], per_cid_total_non_host_vulnerability["info"]))
    logger.info("|- CID: {0} - Sub Total vulnerability High: {1} ".format(args["acc_id"], (per_cid_total_non_host_vulnerability["high"] + per_cid_total_host_vulnerability["high"] )))
    logger.info("|- CID: {0} - Sub Total vulnerability Medium: {1} ".format(args["acc_id"], (per_cid_total_non_host_vulnerability["medium"] + per_cid_total_host_vulnerability["medium"] )))
    logger.info("|- CID: {0} - Sub Total vulnerability Low: {1} ".format(args["acc_id"], (per_cid_total_non_host_vulnerability["low"] + per_cid_total_host_vulnerability["low"] )))
    logger.info("|- CID: {0} - Sub Total vulnerability Info: {1} ".format(args["acc_id"], (per_cid_total_non_host_vulnerability["info"] + per_cid_total_host_vulnerability["info"] )))
    logger.info("|- CID: {0} - Sub Total Unique Host with Vulnerabilities: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["total"]))
    logger.info("|- CID: {0} - Sub Total Host with Vulnerability High: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["high"]))
    logger.info("|- CID: {0} - Sub Total Host with Vulnerability Medium: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["medium"]))
    logger.info("|- CID: {0} - Sub Total Host with Vulnerability Low: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["low"]))
    logger.info("|- CID: {0} - Sub Total Host with Vulnerability Info: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["info"]))
    logger.info("|- CID: {0} - Sub Total Host with Vulnerability High & Medium: {1} ".format(args["acc_id"], per_cid_total_host_with_vulnerability["high_medium"]))
    logger.info("|- CID: {0} - Sub Total Number of Host: {1} ".format(args["acc_id"], per_cid_total_host["total"]))
    logger.info("|- CID: {0} - Sub Total Number of Host Scanned by Alert Logic: {1} ".format(args["acc_id"], per_cid_total_host["scanned"]))

    return per_cid_total_host_vulnerability, per_cid_total_non_host_vulnerability, per_cid_total_host_with_vulnerability, per_cid_total_host

#Get all child under parent
def find_all_child(args):
    myCI = al_ci_client.CloudInsight(args)
    CID_DICT = myCI.get_all_child()

    grand_total_host_vulnerability = {}
    grand_total_host_vulnerability["high"] = 0
    grand_total_host_vulnerability["medium"] = 0
    grand_total_host_vulnerability["low"] = 0
    grand_total_host_vulnerability["info"] = 0

    grand_total_non_host_vulnerability = {}
    grand_total_non_host_vulnerability["high"] = 0
    grand_total_non_host_vulnerability["medium"] = 0
    grand_total_non_host_vulnerability["low"] = 0
    grand_total_non_host_vulnerability["info"] = 0

    grand_total_host_with_vulnerability = {}
    grand_total_host_with_vulnerability["total"] = 0
    grand_total_host_with_vulnerability["high"] = 0
    grand_total_host_with_vulnerability["medium"] = 0
    grand_total_host_with_vulnerability["low"] = 0
    grand_total_host_with_vulnerability["info"] = 0
    grand_total_host_with_vulnerability["high_medium"] = 0

    grand_total_host = {}
    grand_total_host["scanned"] = 0
    grand_total_host["total"] = 0

    #Grab Parent CID vulnerability
    logger.info("### PROCESSING PARENT CID ###")
    per_cid_total_host_vulnerability, per_cid_total_non_host_vulnerability, per_cid_total_host_with_vulnerability, per_cid_total_host = monitor_per_cid(args)

    grand_total_host_vulnerability["high"] = grand_total_host_vulnerability["high"] + per_cid_total_host_vulnerability["high"]
    grand_total_host_vulnerability["medium"] = grand_total_host_vulnerability["medium"] + per_cid_total_host_vulnerability["medium"]
    grand_total_host_vulnerability["low"] = grand_total_host_vulnerability["low"] + per_cid_total_host_vulnerability["low"]
    grand_total_host_vulnerability["info"] = grand_total_host_vulnerability["info"] + per_cid_total_host_vulnerability["info"]

    grand_total_non_host_vulnerability["high"] = grand_total_non_host_vulnerability["high"] + per_cid_total_non_host_vulnerability["high"]
    grand_total_non_host_vulnerability["medium"] = grand_total_non_host_vulnerability["medium"] + per_cid_total_non_host_vulnerability["medium"]
    grand_total_non_host_vulnerability["low"] = grand_total_non_host_vulnerability["low"] + per_cid_total_non_host_vulnerability["low"]
    grand_total_non_host_vulnerability["info"] = grand_total_non_host_vulnerability["info"] + per_cid_total_non_host_vulnerability["info"]

    grand_total_host_with_vulnerability["total"] = grand_total_host_with_vulnerability["total"] + per_cid_total_host_with_vulnerability["total"]
    grand_total_host_with_vulnerability["high"] = grand_total_host_with_vulnerability["high"] + per_cid_total_host_with_vulnerability["high"]
    grand_total_host_with_vulnerability["medium"] = grand_total_host_with_vulnerability["medium"] + per_cid_total_host_with_vulnerability["medium"]
    grand_total_host_with_vulnerability["low"] = grand_total_host_with_vulnerability["low"] + per_cid_total_host_with_vulnerability["low"]
    grand_total_host_with_vulnerability["info"] = grand_total_host_with_vulnerability["info"] + per_cid_total_host_with_vulnerability["info"]
    grand_total_host_with_vulnerability["high_medium"] = grand_total_host_with_vulnerability["high_medium"] + per_cid_total_host_with_vulnerability["high_medium"]

    grand_total_host["scanned"] = grand_total_host["scanned"] + per_cid_total_host["scanned"]
    grand_total_host["total"] = grand_total_host["total"] + per_cid_total_host["total"]

    #Loop through the child for vulnerability
    if len(CID_DICT["accounts"]) > 0:
        logger.info("### PROCESSING CHILD CID ###")

    for CHILD in CID_DICT["accounts"]:
        child_args = deepcopy(args)
        child_args["acc_id"] = CHILD["id"]
        per_cid_total_host_vulnerability, per_cid_total_non_host_vulnerability, per_cid_total_host_with_vulnerability, per_cid_total_host = monitor_per_cid(child_args)

        grand_total_host_vulnerability["high"] = grand_total_host_vulnerability["high"] + per_cid_total_host_vulnerability["high"]
        grand_total_host_vulnerability["medium"] = grand_total_host_vulnerability["medium"] + per_cid_total_host_vulnerability["medium"]
        grand_total_host_vulnerability["low"] = grand_total_host_vulnerability["low"] + per_cid_total_host_vulnerability["low"]
        grand_total_host_vulnerability["info"] = grand_total_host_vulnerability["info"] + per_cid_total_host_vulnerability["info"]

        grand_total_non_host_vulnerability["high"] = grand_total_non_host_vulnerability["high"] + per_cid_total_non_host_vulnerability["high"]
        grand_total_non_host_vulnerability["medium"] = grand_total_non_host_vulnerability["medium"] + per_cid_total_non_host_vulnerability["medium"]
        grand_total_non_host_vulnerability["low"] = grand_total_non_host_vulnerability["low"] + per_cid_total_non_host_vulnerability["low"]
        grand_total_non_host_vulnerability["info"] = grand_total_non_host_vulnerability["info"] + per_cid_total_non_host_vulnerability["info"]

        grand_total_host_with_vulnerability["total"] = grand_total_host_with_vulnerability["total"] + per_cid_total_host_with_vulnerability["total"]
        grand_total_host_with_vulnerability["high"] = grand_total_host_with_vulnerability["high"] + per_cid_total_host_with_vulnerability["high"]
        grand_total_host_with_vulnerability["medium"] = grand_total_host_with_vulnerability["medium"] + per_cid_total_host_with_vulnerability["medium"]
        grand_total_host_with_vulnerability["low"] = grand_total_host_with_vulnerability["low"] + per_cid_total_host_with_vulnerability["low"]
        grand_total_host_with_vulnerability["info"] = grand_total_host_with_vulnerability["info"] + per_cid_total_host_with_vulnerability["info"]
        grand_total_host_with_vulnerability["high_medium"] = grand_total_host_with_vulnerability["high_medium"] + per_cid_total_host_with_vulnerability["high_medium"]

        grand_total_host["scanned"] = grand_total_host["scanned"] + per_cid_total_host["scanned"]
        grand_total_host["total"] = grand_total_host["total"] + per_cid_total_host["total"]

    logger.info("### GRAND TOTAL VULNERABILITIES RELATED TO HOST ###")
    logger.info("Grand Total Host vulnerability High: {0} ".format( grand_total_host_vulnerability["high"]))
    logger.info("Grand Total Host vulnerability Medium: {0} ".format( grand_total_host_vulnerability["medium"]))
    logger.info("Grand Total Host vulnerability Low: {0} ".format( grand_total_host_vulnerability["low"]))
    logger.info("Grand Total Host vulnerability Info: {0} ".format( grand_total_host_vulnerability["info"]))
    logger.info("### GRAND TOTAL VULNERABILITIES RELATED TO NON HOST ###")
    logger.info("Grand Total Non Host vulnerability High: {0} ".format( grand_total_non_host_vulnerability["high"]))
    logger.info("Grand Total Non Host vulnerability Medium: {0} ".format( grand_total_non_host_vulnerability["medium"]))
    logger.info("Grand Total Non Host vulnerability Low: {0} ".format( grand_total_non_host_vulnerability["low"]))
    logger.info("Grand Total Non Host vulnerability Info: {0} ".format( grand_total_non_host_vulnerability["info"]))
    logger.info("### GRAND TOTAL ALL VULNERABILITIES ###")
    logger.info("Grand Total Vulnerabilities: {0} ".format( (grand_total_non_host_vulnerability["high"] + grand_total_host_vulnerability["high"] + grand_total_non_host_vulnerability["medium"] + grand_total_host_vulnerability["medium"] + grand_total_non_host_vulnerability["low"] + grand_total_host_vulnerability["low"] + grand_total_non_host_vulnerability["info"] + grand_total_host_vulnerability["info"]  )))
    logger.info("Grand Total Vulnerability High: {0} ".format( (grand_total_non_host_vulnerability["high"] + grand_total_host_vulnerability["high"])))
    logger.info("Grand Total Vulnerability Medium: {0} ".format( (grand_total_non_host_vulnerability["medium"] + grand_total_host_vulnerability["medium"])))
    logger.info("Grand Total Vulnerability Low: {0} ".format( (grand_total_non_host_vulnerability["low"] + grand_total_host_vulnerability["low"])))
    logger.info("Grand Total Vulnerability Info: {0} ".format( (grand_total_non_host_vulnerability["info"] + grand_total_host_vulnerability["info"])))
    logger.info("### GRAND TOTAL HOST WITH VULNERABILITIES ###")
    logger.info("Grand Total Unique Host with vulnerabilities: {0} ".format( grand_total_host_with_vulnerability["total"]))
    logger.info("Grand Total Host with vulnerability High: {0} ".format( grand_total_host_with_vulnerability["high"]))
    logger.info("Grand Total Host with vulnerability Medium: {0} ".format( grand_total_host_with_vulnerability["medium"]))
    logger.info("Grand Total Host with vulnerability Low: {0} ".format( grand_total_host_with_vulnerability["low"]))
    logger.info("Grand Total Host with vulnerability Info: {0} ".format( grand_total_host_with_vulnerability["info"]))
    logger.info("Grand Total Host with vulnerability High & Medium: {0} ".format( grand_total_host_with_vulnerability["high_medium"]))
    logger.info("### GRAND TOTAL HOST TALLY ###")
    logger.info("|- CID: {0} - Grand Total Number of Host: {1} ".format(args["acc_id"], grand_total_host["total"]))
    logger.info("|- CID: {0} - Grand Total Number of Host Scanned by Alert Logic: {1} ".format(args["acc_id"], grand_total_host["scanned"]))

    LOG_LEVEL=logging.INFO
    logging.basicConfig(format='%(message)s')
    logoutput = logging.getLogger(__name__)
    logoutput.setLevel(LOG_LEVEL)
    logoutput.info("\n")
    logoutput.info("Alert Logic Total Host with Vuln's: {0}".format(grand_total_host_with_vulnerability["total"]))
    logoutput.info("Total hosts scanned by Alert Logic: {0}".format(grand_total_host["scanned"]))

    if (grand_total_host["scanned"] > 0):
        percent_host_vulnerable = float(grand_total_host_with_vulnerability["total"]) / float(grand_total_host["scanned"]) * 100
        percent_host_vulnerable_high_medium = float(grand_total_host_with_vulnerability["high_medium"]) / float(grand_total_host["scanned"]) * 100
    else:
        percent_host_vulnerable = 0
        percent_host_vulnerable_high_medium = 0

    logoutput.info("% Vulnerable Host in Alert Logic: {0}".format(percent_host_vulnerable))
    logoutput.info("Total hosts with High vulnerability: {0}".format(grand_total_host_with_vulnerability["high"]))
    logoutput.info("Total hosts with Med vulnerability: {0}".format(grand_total_host_with_vulnerability["medium"]))
    logoutput.info("Total hosts with Low vulnerability: {0}".format(grand_total_host_with_vulnerability["low"]))
    logoutput.info("\n")
    logoutput.info("% Vulnerable Host (High & Medium) in Alert Logic: {0}".format(percent_host_vulnerable_high_medium))
    logoutput.info("Total hosts with High & Medium vulnerability: {0}".format(grand_total_host_with_vulnerability["high_medium"]))
    logoutput.info("\n")

    total_all_vulnerability = grand_total_non_host_vulnerability["high"] + grand_total_host_vulnerability["high"] + grand_total_non_host_vulnerability["medium"] + grand_total_host_vulnerability["medium"] + grand_total_non_host_vulnerability["low"] + grand_total_host_vulnerability["low"]
    logoutput.info("Alert Logic total vulnerabilities: {0}".format(total_all_vulnerability))
    logoutput.info("AL (Host only) Vulnerabilities High: {0}".format(grand_total_host_vulnerability["high"]))
    logoutput.info("AL (Host only) Vulnerabilities Medium: {0}".format(grand_total_host_vulnerability["medium"]))
    logoutput.info("AL (Host only) Vulnerabilities Low: {0}".format(grand_total_host_vulnerability["low"]))
    logoutput.info("\n")

    logoutput.info("Alert Logic all instances Vuln's High: {0}".format(grand_total_non_host_vulnerability["high"] + grand_total_host_vulnerability["high"]))
    logoutput.info("Alert Logic all instances Vuln's Medium: {0}".format(grand_total_non_host_vulnerability["medium"] + grand_total_host_vulnerability["medium"]))
    logoutput.info("Alert Logic all instances Vuln's Low: {0}".format(grand_total_non_host_vulnerability["low"] + grand_total_host_vulnerability["low"]))
    logoutput.info("\n")

def lambda_handler(event, context):
    logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['query_type']))
    if event['query_type'] == "vulnerability":
        find_all_child(event)
    else:
        logger.error("Event  not supported: {0}".format(event["query_type"]))
    logger.info("End Operations : {0} - Event Type: {1}".format(datetime.now(), event['query_type']))

if __name__ == '__main__':
    #Prepare parser and argument
    parent_parser = argparse.ArgumentParser()

    #REQUIRED PARSER
    required_parser = parent_parser.add_argument_group("Required arguments")
    required_parser.add_argument("--user", required=True, help="User name / email address for Insight API Authentication")
    required_parser.add_argument("--pswd", required=True, help="Password for Insight API Authentication")
    required_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")
    required_parser.add_argument("--cid", required=True, help="Target Alert Logic Customer ID for processing")

    #OPTIONAL
    parent_parser.add_argument("--log", help="Logging level, set to info, debug, error", default="info")

    try:
        args = parent_parser.parse_args()
    except:
        EXIT_CODE = 1
        sys.exit(EXIT_CODE)

    event = {}
    if args.dc == "defender-us-denver":
        event["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-us-ashburn":
        event["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-uk-newport":
        event["yarp"] = "api.cloudinsight.alertlogic.co.uk"

    event["user"] = args.user
    event["password"] = args.pswd
    event["acc_id"] = args.cid
    event["log_level"] = args.log
    event["query_type"] = "vulnerability"

    lambda_handler(event, "ci_scorecard")
