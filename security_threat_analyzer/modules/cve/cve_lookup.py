# ============================================================
# cve_lookup.py — CVE Database Lookup
# NIST NVD API se real world vulnerabilities dhundta hai
# ============================================================

import requests
import json
import os

from modules.cve.cve_parser import CveParser


class CveLookup:
    """
    NIST National Vulnerability Database (NVD) API se
    real world CVE entries dhundta hai.
    """

    # NIST NVD free API URL
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Cache file location (baar baar API call na ho)
    CACHE_FILE = "data/cve_cache.json"

    def __init__(self):
        self.parser = CveParser()
        self.cache = self._load_cache()

    def search(self, keyword: str, max_results: int = 3) -> list:
        """
        Keyword se CVE search karta hai.

        Parameters:
            keyword    : Service name jaise 'FTP', 'SSH', 'HTTP'
            max_results: Kitne results chahiye (default 3)

        Returns:
            List of CVE entries
        """

        # Pehle cache mein check karo
        if keyword in self.cache:
            return self.cache[keyword][:max_results]

        # Internet se fetch karo
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            }

            response = requests.get(
                self.API_URL,
                params=params,
                timeout=10  # 10 seconds wait
            )

            if response.status_code == 200:
                data = response.json()
                results = self.parser.parse(data)

                # Cache mein save karo
                self.cache[keyword] = results
                self._save_cache()

                return results

            else:
                return []

        except requests.exceptions.ConnectionError:
            # Internet nahi hai
            return self._get_offline_data(keyword)

        except requests.exceptions.Timeout:
            # API ne jawab nahi diya
            return self._get_offline_data(keyword)

        except Exception:
            return self._get_offline_data(keyword)

    def search_multiple(self, services: list) -> dict:
        """
        Multiple services ke liye ek saath CVE search karta hai.

        Parameters:
            services: ['FTP', 'SSH', 'HTTP']

        Returns:
            Har service ke CVE results
        """
        all_results = {}

        for service in services:
            results = self.search(service)
            if results:
                all_results[service] = results

        return all_results

    def _load_cache(self) -> dict:
        """Cache file se pehle ka data load karta hai"""
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        """Cache ko file mein save karta hai"""
        try:
            with open(self.CACHE_FILE, "w") as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass

    def _get_offline_data(self, keyword: str) -> list:
        """
        Internet na ho toh offline sample data return karta hai
        """
        offline_data = {
            "FTP": [
                {
                    "id":          "CVE-2021-3434",
                    "description": "FTP service mein authentication bypass vulnerability",
                    "severity":    "HIGH",
                    "score":       7.5
                }
            ],
            "SSH": [
                {
                    "id":          "CVE-2023-38408",
                    "description": "OpenSSH mein remote code execution vulnerability",
                    "severity":    "CRITICAL",
                    "score":       9.8
                }
            ],
            "HTTP": [
                {
                    "id":          "CVE-2021-41773",
                    "description": "Apache HTTP Server mein path traversal vulnerability",
                    "severity":    "CRITICAL",
                    "score":       9.8
                }
            ],
            "RDP": [
                {
                    "id":          "CVE-2019-0708",
                    "description": "Windows RDP mein BlueKeep remote code execution",
                    "severity":    "CRITICAL",
                    "score":       9.8
                }
            ],
            "SMB": [
                {
                    "id":          "CVE-2017-0144",
                    "description": "Windows SMB EternalBlue vulnerability (WannaCry)",
                    "severity":    "CRITICAL",
                    "score":       9.3
                }
            ],
            "TELNET": [
                {
                    "id":          "CVE-2020-10188",
                    "description": "Telnet daemon mein buffer overflow vulnerability",
                    "severity":    "CRITICAL",
                    "score":       9.8
                }
            ],
        }

        return offline_data.get(keyword, [])