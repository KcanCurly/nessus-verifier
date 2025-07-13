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
from requests.auth import HTTPDigestAuth
from urllib.parse import quote

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
            if not "Authentication failure" in res.text and not "Unable to contact server" in res.text and res.text != "0":
                self.on_success(url, hostname, username, password)
                found = True
                        
            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class GrafanaTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Grafana")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "<title>Grafana</title>" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"
            extra = "/login"


            res = requests.post(url + extra, json={"user" : username, "password": password})

            if "Logged in" in res.text:
                self.on_success(url, hostname, username, password)
                found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class HighAvailabilityManagementTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("HIGH AVAILABILITY MANAGEMENT")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "Pacemaker/Corosync Configuration" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "hacluster"
            password = "hacluster"

            res = requests.post(url + "/login", allow_redirects=False, verify=False, data={"username":username, "password": password, "Login": "Login"})

            if res.headers["Location"] == "/manage":
                self.on_success(url, hostname, username, password)
                found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class iDRACTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("iDRAC")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "idrac-start-screen" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            creds = ["root:calvin", "root:ARCADMIN"]

            for cred in creds:
                found = False
                username = cred.split(":")[0]
                password = cred.split(":")[1]

                extra= '/sysmgmt/2015/bmc/session'
                pattern = r'^(https?://[^/]+)'
                match = re.match(pattern, url)
                base_url = match.group(1) # type: ignore

            res = requests.post(base_url + extra, verify=False, headers={"user":username, "password": password}) # type: ignore

            if '"authResult" : 7' in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class IPECSIPPhoneTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("IPECS IP PHONE")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if 'index.asp' in source_code and 'lip-mainframe' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "ipkts"

            res = requests.get(url + "/web/home.asp", verify=False, auth=HTTPDigestAuth(username, password))

            if not "Unauthorized" in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class IRISIDICAMTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("IRIS ID iCAM")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '<title>Iris ID - iCAM Configuration</title>' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "iCAM7000"
            password = "iris7000"

            extra= '/cgi-bin/read'
            pattern = r'^(https?://[^/]+)'
            match = re.match(pattern, url)
            base_url = match.group(1) # type: ignore

            res = requests.post(base_url + extra, allow_redirects=False, verify=False, data={"username":username, "password": password, "logoutBtn": "1"})

            if "Invalid username or password" not in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class LogparseTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Logparse")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '<title>Logparse Signature</title>' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"

            res = requests.post(url, allow_redirects=False, verify=False, data={"eposta":username, "password": password, "login": ""})

            if "Kullanıc adı veya şifreyi hatalı girdiniz" not in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class MyQTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("MyQ")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '/myq/' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "*admin"
            password = "1234"

            res = requests.get(url, verify=False, timeout= 15)
            soup = BeautifulSoup(res.text, "html.parser")

            wsf_request_id = soup.find("input", {"id": "wsfHashId"})["value"] # type: ignore

            script_content = soup.findAll('script', type="text/javascript") # type: ignore
            script_content = script_content[-1].string

            match = re.search(r'"instanceID":"(.*?)"', script_content)
            if match:
                instance_id = match.group(1)


            wsfState='{"async":true,"hash":{},"object":"C4","method":"onLogin","params":[],"ctrlsState":{"C1":{"focusedCtrl":"C10"},"C9":{"modified":true,"value":"*' + username +'"},"C10":{"modified":true,"value":"*' + password + '"}},"deletedServerCtrls":[],"requestID":0,"instanceID":"' + instance_id + "}"
            wsfRequestId = wsf_request_id
            C7="tr"
            pwd=password

            res = requests.post(url, verify=False, timeout= 15, data={"wsfState" : quote(wsfState), "wsfRequestId": wsfRequestId, "C7": C7, "pwd": pwd})

            if not "errorMsg" in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class NetscalerConsoleTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Netscaler Console")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '<title>NetScaler Console</title>' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "nsroot"
            password = "nsroot"

            extra= '/nitro/v1/config/login'
            pattern = r'^(https?://[^/]+)'
            match = re.match(pattern, url)
            base_url = match.group(1) # type: ignore

            res = requests.post(base_url + extra, verify=False, headers={"NITRO_WEB_APPLICATION": "true", "Content-Type": "application/x-www-form-urlencoded"}, data=f"object=%7B%22login%22%3A%7B%22username%22%3A%22{username}%22%2C%22password%22%3A%22{password}%22%7D%7D")

            if not "Invalid username or password" in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class NexthinkConsoleTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Nexthink")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "<title>Nexthink console: Login</title>" in source_code or \
            "NEXThinkPortal" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"

            token_re = r"name=\"csrf_nexthink_token\" value=\"(.*)\" " 

            res1 = requests.get(url, verify=False)

            match = re.search(token_re, res1.text)

            if match:
                token = match.group(1)

                res = requests.post(url + "/", verify=False, data={"csrf_nexthink_token":token, "username": username, "password": password, "login": "Sign+In"})

                if not "Authentication failed! Your username and/or password is invalid" in res.text:
                        self.on_success(url, hostname, username, password)
                        found = True

                if not found:
                    self.on_failure(url, hostname)

                    return URL_STATUS.NOT_VALID
                return URL_STATUS.VALID
            return URL_STATUS.NOT_VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class OpinnateTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Opinnate")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '<title>Opinnate</title>' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "opinnate"

            extra= '/api/login'
            pattern = r'^(https?://[^/]+)'
            match = re.match(pattern, url)
            base_url = match.group(1) # type: ignore

            res = requests.post(base_url + extra, verify=False, data={"username":username, "password": password})

            if 'Login Succesfull' in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class OracleLightsoutManagerTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("ORACLE INTEGRATED LIGHTS OUT MANAGER")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if 'Integrated Lights Out Manager' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            credentials = ["root:changeme", "admin:welcome1", "admin:changeme"]

            for cred in credentials:
                cred = cred.split(":")
                username = cred[0]
                password = cred[1]
                extra = "/iPages/i_login.asp"
                extra1 = '/iPages/loginProcessor.asp'
                pattern = r'^(https?://[^/]+)'
                match = re.match(pattern, url)
                base_url = match.group(1) # type: ignore
                res = requests.get(url + extra, verify=False, timeout=15)
                cookies = res.cookies
                soup = BeautifulSoup(res.text, 'html.parser')

                scripts = soup.find_all('script')

                for script in scripts:
                    if script.string and "loginToken" in script.string: # type: ignore

                        match = re.search(r'"loginToken", "(.*?)"\);', script.string) # type: ignore
                        login_token = match.group(1) # type: ignore

                        res = requests.post(base_url + extra1, data={"username" : username, "password": password, "loginToken": login_token}, verify=False, timeout=15, cookies=cookies)

                        if "/iPages/suntab.asp" in res.text and res.status_code == 200:
                            self.on_success(url, hostname, username, password)
                            found = True

                        break

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class StoredIQTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("IBM StoredIQ")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '<title>IBM StoredIQ' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"

            res = requests.post(url + "/login", verify=False, data={"email":username, "password": password})

            if "Log in failed" not in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class StorwareTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Storware")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if '../assets/img/apple-icon.png' in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "vPr0tect"
            extra = "/api/session/login"
            res = requests.post(url + extra, json={"login" : username, "password": password})

            if res.status_code not in ["401"]:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class SynergySkyTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Synergy Sky")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "<title>Synergy SKY Appliance</title>" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin@localhost"
            password = "Newpassword6"

            res = requests.get(url + "/config", verify=False, auth=(username, password))

            if res.status_code in [200]:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class UNISPHERETemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("UNISPHERE FOR POWERMAX")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "Welcome to EMC Unisphere for VMAX" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "smc"
            password = "smc"

            res = requests.post(url + "/univmax/restapi/common/login", auth=(username, password), timeout= 15, verify=False, headers={
                "U4V-REST-APP-NAME" : "univmax" # needed
            })

            if "Unauthorized" not in res.text and res.status_code == 200:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class WatsonTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Watson")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "/Watson/" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"

            res = requests.post(url, verify=False, data={"username":username, "password": password})

            if not "Authentication failed" in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class XormonTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Xormon")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "Xormon is performance monitoring tool for servers, storage, SAN and LAN" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin@xormon.com"
            password = "xorux4you"

            res = requests.post(url + "/login", verify=False, data={"username":username, "password":password})

            if res.status_code != "401":
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class XoruxTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("XORUX LPAR2RRD")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "/lpar2rrd/" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "admin"
            password = "admin"

            res = requests.get(url + "/lpar2rrd/", verify=False, auth=(username, password))

            if not "Unauthorized" in res.text:
                self.on_success(url, hostname, username, password)
                found = True

            if not found:
                self.on_failure(url, hostname)

            found = False

            res = requests.get(url + "/stor2rrd/", verify=False, auth=(username, password))

            if not "Unauthorized" in res.text:
                self.on_success(url, hostname, username, password)
                found = True
            if not found:
                self.on_failure(url, hostname)

            found = False

            res = requests.post(url + "/xormon/login", verify=False, data={"username":"admin@xormon.com", "password":"xorux4you"})

            if res.status_code not in (401, 404):
                self.on_success(url, hostname, username, password)
                found = True
            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID

        else:
            return URL_STATUS.NOT_RECOGNIZED
        
class ZabbixTemplate(SiteTemplateBase):
    def __init__(self):
        super().__init__("Zabbix")

    def check(self, url, source_code, verbose=False) -> URL_STATUS:
        if "zabbix-logo" in source_code:
            found = False
            hostname = hostname = SiteTemplateBase.get_dns_name(url)

            username = "Admin"
            password = "zabbix"

            res = requests.post(url + "/index.php", verify=False, data={"name":username, "password": password, "enter": "Sign+in"})

            if not "Incorrect user name or password or account is temporarily blocked" in res.text:
                    self.on_success(url, hostname, username, password)
                    found = True

            if not found:
                self.on_failure(url, hostname)

                return URL_STATUS.NOT_VALID
            return URL_STATUS.VALID
        else:
            return URL_STATUS.NOT_RECOGNIZED