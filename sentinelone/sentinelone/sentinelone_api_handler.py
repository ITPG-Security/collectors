from datetime import datetime
import requests
import re

from pyobas.helpers import OpenBASCollectorHelper

class SentinelOneApiHandler:
    def __init__(self, helper: OpenBASCollectorHelper, api_token: str, base_url: str, use_file_path: bool):
        self.helper = helper
        self.api_token = api_token
        self.base_url = base_url
        self.use_file_path = use_file_path
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'ApiToken {self.api_token}'})

    def _convert_file_path(self, file_path: str):
        # Check for OpenBAS agent
        result = ""
        if "OBAS Agent\\execution-" in file_path:
            match = re.search(r"OBAS Agent\\([^\\]+)\\", file_path)
            if match:
                result = match.group(1)
        return result


    def _cleanup_events(self, threats: list):
        results = []
        for threat in threats:
            results.append({
                "id":threat["id"],
                "filename": threat["threatInfo"]["threatName"],
                "parent_details": {"filename": threat["threatInfo"]["originatorProcess"]},
                "device": {"hostname": threat["agentRealtimeInfo"]["agentComputerName"]},
                "mitigation_status": threat["threatInfo"]["mitigationStatus"],
                "filepath": self._convert_file_path(threat["threatInfo"]["filePath"])
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
            return self._cleanup_events(threats)

        self.helper.collector_logger.error(
            "Could not fetch alerts from the SentinelOne backend."
        )
        return []
    
