from datetime import datetime
import requests
import re
import csv

from pyobas.helpers import OpenBASCollectorHelper

class SentinelOneApiHandler:
    def __init__(self, helper: OpenBASCollectorHelper, api_token: str, base_url: str):
        self.helper = helper
        self.api_token = api_token
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'ApiToken {self.api_token}'})

    def _fix_events(self, threats: list):
        results = []
        for threat in threats:
            quarantineResults = self._get_quarantine_report(threat)
            results.append({
                "id":threat["id"],
                "filename": threat["threatInfo"]["threatName"],
                "parent_details": {"filename": threat["threatInfo"]["originatorProcess"]},
                "device": {"hostname": threat["agentRealtimeInfo"]["agentComputerName"]},
                "mitigation_status": threat["threatInfo"]["mitigationStatus"],
                "quarantine_result": quarantineResults
            })
        return results

    def get_threats(self, start_time: datetime, cursor:str=None):
        parameters = {
            "createdAt__gt": start_time.isoformat(),
        }
        if cursor:
            parameters["cursor"] = cursor
        # Obtain Threats (SentinelOne's version of Alerts)
        response = self.session.get(url=f"{self.base_url}/web/api/v2.1/threats", params=parameters)
        threats = []
        if response.status_code == 200:
            results = response.json()
            threats.extend(results["data"])
            if results["pagination"]["nextCursor"]:
                self.helper.collector_logger.debug(
                    f"Collecting next page with cursor: '{results["pagination"]["nextCursor"]}'"
                )
                threats.extend(self.get_threats(start_time, results["pagination"]["nextCursor"]))
            return self._fix_events(threats)

        self.helper.collector_logger.error(
            "Could not fetch alerts from the SentinelOne backend."
        )
        return threats
    
    def _get_quarantine_report(self, threat):
        for mitigation in threat["mitigationStatus"]:
            if mitigation["action"] == "quarantine":
                response = self.session.get(url=f"{self.base_url}web/api/v2.1/threats/mitigation-report/{mitigation["reportId"]}")
                if response.status_code == 200:
                    csvResult = response.text
                    return self._parse_quarantine_report(csvResult)
                self.helper.collector_logger.error(f"Could not fetch quarantine report from the SentinelOne backend. Code:{str(response.status_code)}")
        return []
    
    def _parse_quarantine_report(self, csvReport:str):
        resultList=[]
        # The [5:] is needed to skip a comment and header. Format is TimeGenerated,Path,Status
        readerResult = csv.reader(csvReport.split('\n')[5:])
        for row in readerResult:
            row = list(filter(None, row))
            if len(row) == 3:
                # obas-implant is the prefix of the value OpenBAS searches for. This is to eliminate comparasons.
                if re.search('obas-implant', row[1]) and row[2] == "success":
                    resultList.append(row[1])
        return resultList
