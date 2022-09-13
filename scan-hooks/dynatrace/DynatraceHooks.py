import os
from sre_compile import isstring
import requests

# Custom Hook to integrate Dynatrace with OWASP ZAP
#
# This integration will:
# - Configure log attributes, log metrics and log events in DT
# - Create a demo dashboard
# - Run a ZAP scan
# - Push all log lines (warning and failures) to Dynatrace
# - Attach events to the matching entity ID(s) (eg. Applications) for scan results
# - Automatically create a DT problem if a ZAP scan is found to be vulnerable
#
# Prerequisites
# - A Dynatrace tenant (free trial: https://dynatrace.com/trial)
# - A Dynatrace API token with the following permissions: `entities.read`, `logs.ingest`, (optional if creating DT config) `settings.write` and (optional if creating DT config) `WriteConfig`
#
# Usage
#
# Configure the variables below and save this file as DynatraceHooks.py
# Run ZAP with docker:
# -- Windows --
# docker run ^
# -v %cd%:/zap/wrk:rw ^
# -e dt_url="https://abc12345.live.dynatrace.com" ^
# -e dt_api_token="dt0c01.*********" ^
# -e dt_entity_selector="type(APPLICATION),entityName.equals(PROD - example.com)" ^
# -e dt_create_config="true" ^
# -t owasp/zap2docker-stable zap-baseline.py ^
# -t https://example.com ^
# --hook=DynatraceHooks.py
#
# -- Mac / Linux --
# docker run \
# -v %cd%:/zap/wrk:rw \
# -e dt_url="https://abc12345.live.dynatrace.com" \
# -e dt_api_token="dt0c01.*********" \
# -e dt_entity_selector="type(APPLICATION),entityName.equals(PROD - example.com)" \
# -e dt_create_config="true" \
# -t owasp/zap2docker-stable zap-baseline.py \
# -t https://example.com \
# --hook=DynatraceHooks.py
#
# For the very first run, set the -e dt_create_config="True"
# for all subsequent runs, where you know the configuration has been created, you can omit
# In which case, it is assumed that configuration already exists in the tenant
# and this means you can drop the write.settings permission from the API token
#
# Optional Additional Parameters
# - failure_threshold (default = 0)
# - error_if_fail (default = True)
# - debug_mode (default = False)
# - create_dt_config (default = False)

##########################################
# DO NOT MODIFY ANYTHING BELOW THIS LINE #
##########################################

# https://{TenantID}.live.dynatrace.com OR
# https://{EnvironmentActiveGateIP}/e/{TenantID}
dt_url = os.getenv("dt_url", "")
dt_api_token = os.getenv("dt_api_token","")

# Set to True if you want to send a ERROR log when ZAP detects failures.
# Also configurable is the number of ZAP failures required before sending ERROR event
# Normally it makes sense to leave this as 0. More than 0 ZAP failures means the test failed
ERROR_IF_FAIL = os.getenv("error_if_fail", True)

ZAP_FAILURE_THRESHOLD = int(os.getenv("failure_threshold", 0))

# Set to True for debug output. These entries are sent to DT log ingest.
DEBUG_MODE = os.getenv("debug_mode", False)
if isstring(DEBUG_MODE) and (DEBUG_MODE.lower() =="true" or DEBUG_MODE == "1"):
    DEBUG_MODE = True
else: DEBUG_MODE = False

dt_entity_selector = os.getenv("dt_entity_selector","")

# If True, script will add required configuration to your tentant. Use this mainly for hte very first run,
# All subsequent runs can drop the write.settings permission and we assume all config exists.
DT_CREATE_CONFIG = os.getenv("dt_create_config", "False")
if isstring(DT_CREATE_CONFIG) and (DT_CREATE_CONFIG.lower() == "true" or DT_CREATE_CONFIG == "1"):
    DT_CREATE_CONFIG = True
else: DT_CREATE_CONFIG = False

if dt_url == "" or dt_api_token == "" or dt_entity_selector == "":
    print("ERROR: Required parameters missing. Following env vars must be set: 'dt_url', 'dt_api_token' and 'dt_entity_selector'. Please try again.")
    exit(1)

# remove trailing slash if present on dt_url
if dt_url[-1:] == "/": dt_url = dt_url[:-1]

dt_headers = {
    "Authorization": f"Api-Token {dt_api_token}",
    "Accept": "application/json; charset=utf-8",
    "Content-Type": "application/json; charset=utf-8"
}
zap_results = {}

# DT Helper
# Create configuration
# TODO: Move to monaco when monaco supports settings 2.0
# A 400 response code signals all config already exists
# A 207 for a GET means some config already exists. Note a 207
# A 200 means all config exists
def create_dt_config():
    ##########################
    # Create log attributes  #
    ##########################
    params = {
        "schemaIds": "builtin:logmonitoring.log-custom-attributes",
        "scopes": "environment",
        "validateOnly": False
    }
    payload = [{
        "schemaId": "builtin:logmonitoring.log-custom-attributes",
        "scope":"environment",
        "value":{
            "key":"zap_pass_count",
            "aggregableAttribute": True
        }
    }, {
        "schemaId": "builtin:logmonitoring.log-custom-attributes",
        "scope":"environment",
        "value":{
            "key":"zap_warn_count",
            "aggregableAttribute": True
        }
    }, {
        "schemaId": "builtin:logmonitoring.log-custom-attributes",
        "scope":"environment",
        "value":{
            "key":"zap_fail_count",
            "aggregableAttribute": True
        }
    }]

    requests.post(url=f"{dt_url}/api/v2/settings/objects",headers=dt_headers,params=params, json=payload)

    ##########################
    # Create log metrics     #
    ##########################
    params = {
        "schemaIds": "builtin:logmonitoring.schemaless-log-metric",
        "scopes": "environment",
        "validateOnly": False
    }
    payload = [{
    "schemaId": "builtin:logmonitoring.schemaless-log-metric",
    "scope": "environment",
    "value":{
        "enabled": True,
        "key": "log.zap.pass_count",
        "query": "",
        "measure": "ATTRIBUTE",
        "measureAttribute": "zap_pass_count",
        "dimensions":["dt.entity.application"]
        }
    }, {
    "schemaId": "builtin:logmonitoring.schemaless-log-metric",
    "scope": "environment",
    "value":{
        "enabled": True,
        "key": "log.zap.warn_count",
        "query": "",
        "measure": "ATTRIBUTE",
        "measureAttribute": "zap_warn_count",
        "dimensions":["dt.entity.application"]
        }
    }, {
    "schemaId": "builtin:logmonitoring.schemaless-log-metric",
    "scope": "environment",
    "value":{
        "enabled": True,
        "key": "log.zap.fail_count",
        "query": "",
        "measure": "ATTRIBUTE",
        "measureAttribute": "zap_fail_count",
        "dimensions":["dt.entity.application"]
    }
    }]

    
    requests.post(url=f"{dt_url}/api/v2/settings/objects",headers=dt_headers,params=params, json=payload)

    ##########################
    # Create log events      #
    ##########################
    params = {
        "schemaIds": "builtin:logmonitoring.log-events",
        "scopes": "environment",
        "validateOnly": False
    }
    payload = [{
    "schemaId": "builtin:logmonitoring.log-events",
    "scope": "environment",
    "value": {
        "enabled": True,
        "summary": "ZAP Scan Results (Standard)",
        "query": "log.source=\"ZAP\" and loglevel=\"INFO\" and content=\"ZAP Scan Results\"",
        "eventTemplate": {
          "title": "ZAP Scan Results",
          "description": "Passed tests: {zap_pass_count}\nWarning tests: {zap_warn_count}\nFailed tests: {zap_fail_count}",
          "eventType": "INFO",
          "metadata": [
            {
              "metadataKey": "dt.entity.application",
              "metadataValue": "{dt.entity.application}"
            }
          ]
        }
      }
    }, {
    "schemaId": "builtin:logmonitoring.log-events",
    "scope": "environment",
    "value": {
        "enabled": True,
        "summary": "ZAP Scan: Vulnerable Application",
        "query": "log.source=\"ZAP\" and loglevel=\"ERROR\" and content=\"ZAP Scan Results\"",
        "eventTemplate": {
          "title": "Vulnerable Application Scan [ZAP]",
          "description": "ZA Proxy found vulnerabilities in your application.\n\nFailed tests: {zap_fail_count}\nWarning tests: {zap_warn_count}\nPassed tests: {zap_pass_count}",
          "eventType": "CUSTOM_ALERT",
          "davisMerge": True,
          "metadata": [
            {
              "metadataKey": "dt.entity.application",
              "metadataValue": "{dt.entity.application}"
            }
          ]
        }
      }
    }]

    requests.post(url=f"{dt_url}/api/v2/settings/objects",headers=dt_headers,params=params, json=payload)

    ######################
    # Create dashboard   #
    ######################
    params = {
        "schemaIds": "builtin:logmonitoring.schemaless-log-metric",
        "scopes": "environment",
        "validateOnly": False
    }
    payload = {
                "dashboardMetadata": {
                    "name": "ZA Proxy Dashboard",
                    "shared": False,
                    "owner": "opensource@dynatrace.com",
                    "dashboardFilter": None,
                    "tags": [ "open-source", "za-proxy"],
                    "popularity": 2,
                    "tilesNameSize": "",
                    "hasConsistentColors": False
                    },
                    "tiles": [{
                        "name": "Passing Tests",
                        "nameSize": "",
            "tileType": "DATA_EXPLORER",
            "configured": True,
            "bounds": {
                "top": 76,
                "left": 0,
                "width": 304,
                "height": 304
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "customName": "Data explorer results",
        "queries": [{
            "id": "A",
            "metric": "log.zap.pass_count",
            "spaceAggregation": None,
            "timeAggregation": "DEFAULT",
            "splitBy": [],
            "sortBy": "DESC",
            "filterBy": {
            "filter": None,
            "globalEntity": None,
            "filterType": None,
            "filterOperator": None,
            "entityAttribute": None,
            "relationship": None,
            "nestedFilters": [],
            "criteria": []
            },
            "limit": 100,
            "metricSelector": None,
            "foldTransformation": None,
            "enabled": True,
            "generatedMetricSelector": None
        }],
        "visualConfig": {
        "type": "SINGLE_VALUE",
        "global": {
            "theme": None,
            "threshold": None,
            "seriesType": None,
            "hasTrendline": None,
            "hideLegend": False
        },
        "rules": [{
            "matcher": "A:",
            "unitTransform": None,
            "valueFormat": None,
            "properties": {
                "color": "DEFAULT",
                "seriesType": None,
                "alias": None
            },
            "seriesOverrides": []
            }],
        "axes": {
            "xAxis": {
            "displayName": None,
            "visible": True
            },
            "yAxes": []
        },
        "heatmapSettings": {
            "yAxis": "VALUE",
            "yAxisBuckets": None,
            "xAxisBuckets": None
        },
        "singleValueSettings": {
            "showTrend": True,
            "showSparkLine": True,
            "linkTileColorToThreshold": True
        },
        "thresholds": [{
            "axisTarget": "LEFT",
            "columnId": None,
            "rules": [
                {
                "value": None,
                "color": "#7dc540"
                },
                {
                "value": None,
                "color": "#f5d30f"
                },
                {
                "value": None,
                "color": "#dc172a"
                }
            ],
            "queryId": "",
            "visible": True
            }],
        "tableSettings": {
            "isThresholdBackgroundAppliedToCell": False
        },
        "graphChartSettings": {
            "connectNones": False
        },
        "honeycombSettings": {
            "showHive": True,
            "showLegend": True,
            "showLabels": False
        }
        },
        "queriesSettings": {
        "resolution": "",
        "foldTransformation": None,
        "foldAggregation": None
        },
        "metricExpressions": [
        "resolution=Inf&(log.zap.pass_count:splitBy():sort(value(auto,descending)):limit(100)):limit(100):names",
        "resolution=None&(log.zap.pass_count:splitBy():sort(value(auto,descending)):limit(100))"
        ]
        },
        {
        "name": "Warning Tests",
        "nameSize": "",
        "tileType": "DATA_EXPLORER",
        "configured": True,
        "bounds": {
        "top": 76,
        "left": 304,
        "width": 304,
        "height": 304
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "customName": "Data explorer results",
        "queries": [
        {
            "id": "A",
            "metric": "log.zap.warn_count",
            "spaceAggregation": None,
            "timeAggregation": "DEFAULT",
            "splitBy": [],
            "sortBy": "DESC",
            "filterBy": {
            "filter": None,
            "globalEntity": None,
            "filterType": None,
            "filterOperator": None,
            "entityAttribute": None,
            "relationship": None,
            "nestedFilters": [],
            "criteria": []
            },
            "limit": 100,
            "metricSelector": None,
            "foldTransformation": None,
            "enabled": True,
            "generatedMetricSelector": None
        }
        ],
        "visualConfig": {
        "type": "SINGLE_VALUE",
        "global": {
            "theme": None,
            "threshold": None,
            "seriesType": None,
            "hasTrendline": None,
            "hideLegend": False
        },
        "rules": [
            {
            "matcher": "A:",
            "unitTransform": None,
            "valueFormat": None,
            "properties": {
                "color": "DEFAULT",
                "seriesType": None,
                "alias": None
            },
            "seriesOverrides": []
            }
        ],
        "axes": {
            "xAxis": {
            "displayName": None,
            "visible": True
            },
            "yAxes": []
        },
        "heatmapSettings": {
            "yAxis": "VALUE",
            "yAxisBuckets": None,
            "xAxisBuckets": None
        },
        "singleValueSettings": {
            "showTrend": True,
            "showSparkLine": True,
            "linkTileColorToThreshold": True
        },
        "thresholds": [
            {
            "axisTarget": "LEFT",
            "columnId": None,
            "rules": [{
                "value": None,
                "color": "#7dc540"
                },
                {
                "value": None,
                "color": "#f5d30f"
                },
                {
                "value": None,
                "color": "#dc172a"
                }],
            "queryId": "",
            "visible": True
            }
        ],
        "tableSettings": {
            "isThresholdBackgroundAppliedToCell": False
        },
        "graphChartSettings": {
            "connectNones": False
        },
        "honeycombSettings": {
            "showHive": True,
            "showLegend": True,
            "showLabels": False
        }
        },
        "queriesSettings": {
        "resolution": "",
        "foldTransformation": None,
        "foldAggregation": None
        },
        "metricExpressions": [
        "resolution=Inf&(log.zap.warn_count:splitBy():sort(value(auto,descending)):limit(100)):limit(100):names",
        "resolution=None&(log.zap.warn_count:splitBy():sort(value(auto,descending)):limit(100))"
        ]
        },
        {
        "name": "Failed Tests",
        "nameSize": "",
        "tileType": "DATA_EXPLORER",
        "configured": True,
        "bounds": {
        "top": 76,
        "left": 608,
        "width": 304,
        "height": 304
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "customName": "Data explorer results",
        "queries": [{
            "id": "A",
            "metric": "log.zap.fail_count",
            "spaceAggregation": None,
            "timeAggregation": "DEFAULT",
            "splitBy": [],
            "sortBy": "DESC",
            "filterBy": {
            "filter": None,
            "globalEntity": None,
            "filterType": None,
            "filterOperator": None,
            "entityAttribute": None,
            "relationship": None,
            "nestedFilters": [],
            "criteria": []
            },
            "limit": 100,
            "metricSelector": None,
            "foldTransformation": None,
            "enabled": True,
            "generatedMetricSelector": None
        }],
        "visualConfig": {
        "type": "SINGLE_VALUE",
        "global": {
            "theme": None,
            "threshold": None,
            "seriesType": None,
            "hasTrendline": None,
            "hideLegend": False
        },
        "rules": [{
            "matcher": "A:",
            "unitTransform": None,
            "valueFormat": None,
            "properties": {
                "color": "DEFAULT",
                "seriesType": None,
                "alias": None
            },
            "seriesOverrides": []
            }
        ],
        "axes": {
            "xAxis": {
            "displayName": None,
            "visible": True
            },
            "yAxes": []
        },
        "heatmapSettings": {
            "yAxis": "VALUE",
            "yAxisBuckets": None,
            "xAxisBuckets": None
        },
        "singleValueSettings": {
            "showTrend": True,
            "showSparkLine": True,
            "linkTileColorToThreshold": True
        },
        "thresholds": [
            {
            "axisTarget": "LEFT",
            "columnId": None,
            "rules": [{
                "value": 0,
                "color": "#7dc540"
                },
                {
                "value": None,
                "color": "#f5d30f"
                },
                {
                "value": 1,
                "color": "#dc172a"
                }],
            "queryId": "",
            "visible": True
            }
        ],
        "tableSettings": {
            "isThresholdBackgroundAppliedToCell": False
        },
        "graphChartSettings": {
            "connectNones": False
        },
        "honeycombSettings": {
            "showHive": True,
            "showLegend": True,
            "showLabels": False
        }
        },
        "queriesSettings": {
        "resolution": "",
        "foldTransformation": None,
        "foldAggregation": None
        },
        "metricExpressions": [
        "resolution=Inf&(log.zap.fail_count:splitBy():sort(value(auto,descending)):limit(100)):limit(100):names",
        "resolution=None&(log.zap.fail_count:splitBy():sort(value(auto,descending)):limit(100))"
        ]
        },
        {
        "name": "Markdown",
        "nameSize": "",
        "tileType": "MARKDOWN",
        "configured": True,
        "bounds": {
        "top": 380,
        "left": 0,
        "width": 304,
        "height": 76
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "markdown": "[Show ZAP Output for pass logs](ui/log-monitoring?gtf=-30m&gf=all&query=log.source%3D%22zap%22%20AND%20status%3D%22info%22%20AND%20content%20%3D%20%22confidence%22&sortDirection=desc&baseQuery=&advancedQueryMode=True&visibleColumns=timestamp&visibleColumns=status&visibleColumns=content)"
        },
        {
        "name": "Markdown",
        "nameSize": "",
        "tileType": "MARKDOWN",
        "configured": True,
        "bounds": {
        "top": 380,
        "left": 304,
        "width": 304,
        "height": 76
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "markdown": "[Show ZAP Output for warn logs](ui/log-monitoring?gtf=-30m&gf=all&query=log.source%3D%22zap%22%20AND%20status%3D%22warn%22%20AND%20content%20%3D%20%22confidence%22&sortDirection=desc&baseQuery=&advancedQueryMode=True&visibleColumns=timestamp&visibleColumns=status&visibleColumns=content)"
        },
        {
        "name": "Markdown",
        "nameSize": "",
        "tileType": "MARKDOWN",
        "configured": True,
        "bounds": {
        "top": 380,
        "left": 608,
        "width": 304,
        "height": 76
        },
        "tileFilter": {
        "timeframe": None,
        "managementZone": None
        },
        "markdown": "[Show ZAP Output for fail logs](ui/log-monitoring?gtf=-30m&gf=all&query=log.source%3D%22zap%22%20AND%20status%3D%22warn%22%20AND%20content%20%3D%20%22confidence%22&sortDirection=desc&baseQuery=&advancedQueryMode=True&visibleColumns=timestamp&visibleColumns=status&visibleColumns=content)\n\n## [Show problems](ui/problems?gtf=yesterday&gf=all&text=zap%20scan)"
        }]
        }

    requests.post(url=f"{dt_url}/api/config/v1/dashboards",headers=dt_headers,params=params, json=payload)

# Create DT configuration
if DT_CREATE_CONFIG:
    create_dt_config()

# ZAP Hook
# This provides a list of WARN and FAIL alerts
# Pass them as-is to Dynatrace log ingest
# Note: pre_exit hook is still required to get pass stats (overall pass / warning / fail stats)
def zap_get_alerts_wrap(alert_dict):

    for alert in alert_dict:
        alerts_for_code = alert_dict[alert]
        status = "INFO"
        for alert_for_code in alerts_for_code:
            risk = alert_for_code['risk']
            
            # If risk is Medium, status is WARN
            if risk == "Medium": status = "WARN"
            # If risk is High, status is ERROR
            if risk == "High": status = "ERROR"
            
            log_entry = generate_dt_log_entry(status,"", alert_for_code)
            send_log(log_entry)

# ZAP Hook
# This hook provides access to the pass / warning  fail count
# Used to send an event to the entity ID and send log entries to log ingest
def pre_exit(fail_count, warn_count, pass_count):
    zap_results = {
        "zap_pass_count": pass_count,
        "zap_warn_count": warn_count,
        "zap_fail_count": fail_count
    }

    if DEBUG_MODE:
        log_entry = generate_dt_log_entry("DEBUG","Entering ZAP pre_exit hook. About to exit ZAP...", zap_results)
        send_log(log_entry)

    # If ERROR_IF_FAIL is set to True AND
    # the zap_fail_count > ZAP_FAILURE_THRESHOLD set log line status to Error.
    status = "INFO"
    if ERROR_IF_FAIL and zap_results['zap_fail_count'] > ZAP_FAILURE_THRESHOLD:
        status = "ERROR"
        if DEBUG_MODE:
            log_entry = generate_dt_log_entry("DEBUG","error_if_fail is True and ZAP detected failures", zap_results)
            send_log(log_entry)

    # Lookup the entity id(s) and add to properties
    entity_ids = get_dt_entity_ids()

    # For each entity ID, send a distint logline
    # While setting dt.entity.application
    # Which is crucial to tie the log line to the APPLICATION for root cause analysis
    # Send results to Dynatrace using Log Ingest
    for id in entity_ids:
        app_id = {
            "dt.entity.application": id
        }
        # Add this to zap_results
        # Note: Adding same key in this loop is OK becuase it will be overwritten. Multiple identical keys aren't added.
        zap_results.update(app_id)
        
        zap_results_log_entry = generate_dt_log_entry(status, f"ZAP Scan Results for {app_id}", zap_results)
        send_log(zap_results_log_entry)

# DT Helper Method
# The send_debug parameter should not be used by you
# It is for internal use only to prevent an endless loop during debug mode.
def send_log(log_entry):

    response = requests.post(url=f"{dt_url}/api/v2/logs/ingest", headers=dt_headers, json=log_entry)
    
    # If something is going wrong with log ingest, it is most likely that HTTPS endpoints are not available.
    # Print errors locally otherwise we may never see them
    if DEBUG_MODE: print(f"Log Ingestion Response Code: {response.status_code}. Response Text: {response.text}")

# DT Helper Method
# All log lines:
# - Are automatically set as root cause relevant for DT
# - Have the ZAP results included (zap_pass_count, zap_warn_count and zap_fail_count)
# - If provided, properties (provided as a dictionary of K/V pairs) are added
def generate_dt_log_entry(status, content, properties):

    log_entry = {
        "log.source": "ZAP",
        "status": status,
        "content": content,
        "dt.events.root_cause_relevant": True
    }
    # Add zap_results to log_entry
    log_entry.update(zap_results)
    # If provided with additional K/V properties, add them.
    if properties is not None:
        log_entry.update(properties)
    
    return log_entry

# DT Helper IDs
# Get Entity ID(s) for the provided tags
def get_dt_entity_ids():
    log_entry = generate_dt_log_entry("INFO", f"Looking up APPLICATION ID(s) for entitySelector: {dt_entity_selector}", None)
    send_log(log_entry)

    params = {
        "entitySelector": dt_entity_selector
    }

    response = requests.get(url=f"{dt_url}/api/v2/entities",params=params, headers=dt_headers)
    json_response = response.json()

    log_entry = generate_dt_log_entry("INFO","Got json_response for entities", json_response)
    send_log(log_entry)
    
    if json_response['totalCount'] == 0:
        log_entry = generate_dt_log_entry("ERROR", f"Found no entity ID(s) for: {dt_entity_selector}", None)
        send_log(log_entry)
    
    entity_ids = []
    for entity in json_response['entities']:
        entity_ids.append(entity['entityId'])
    
    log_entry = generate_dt_log_entry("INFO", f"Found {len(entity_ids)} entity IDs for: {dt_entity_selector}: {entity_ids}", None)
    send_log(log_entry)

    return entity_ids