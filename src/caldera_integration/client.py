from __future__ import annotations

from typing import Any, Dict, Optional

import requests


class CalderaClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, *, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["KEY"] = self.api_key
        return headers

    def trigger_operation(self, operation_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Placeholder for future CALDERA operation triggering.
        """
        response = requests.post(
            f"{self.base_url}/api/v2/operations",
            json=operation_payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        return {
            "status_code": response.status_code,
            "message": "CALDERA trigger placeholder executed",
        }

    def fetch_logs(self, operation_id: str) -> Dict[str, Any]:
        """
        Placeholder for future CALDERA log retrieval.
        """
        response = requests.get(
            f"{self.base_url}/api/v2/operations/{operation_id}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        return {
            "status_code": response.status_code,
            "message": "CALDERA fetch_logs placeholder executed",
        }
