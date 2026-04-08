import json
from collections import deque
from dataclasses import asdict
from datetime import datetime

class ReportManager:
    def __init__(self, history_size=10):
        self.__history = deque(maxlen=history_size)

    def add_to_history(self, cert_list):
        self.__history.append({
            "timestamp": str(datetime.now()),
            "data": [asdict(c) for c in cert_list]
        })

    def save_json_report(self, cert_list, filename="cert_report.json"):
        report = {"certificates": []}
        for cert in cert_list:
            report["certificates"].append({
                "domain": cert.domain,
                "san": cert.san,
                "issuer": cert.issuer,
                "valid_to": cert.valid_to.strftime("%Y-%m-%d"),
                "days_left": cert.days_left,
                "status": cert.status
            })

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)