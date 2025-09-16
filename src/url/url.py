import argparse
from collections import defaultdict
import os
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, Comment
import re
import warnings
import socket
from rich.live import Live
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn
from rich.table import Column
from rich.console import Group
from rich.panel import Panel
from src.url.templates import ArisconnectTemplate, FlexNetPublishTemplate, FortigateTemplate, URL_STATUS, FujitsuWebServerTemplate, GrafanaTemplate, HighAvailabilityManagementTemplate, IBMSoftwareAGTemplate, IPECSIPPhoneTemplate, IRISIDICAMTemplate, JHipsterRegistryManagementTemplate, LogparseTemplate, MyQTemplate, NetscalerConsoleTemplate, NexthinkConsoleTemplate, OpinnateTemplate, OracleLightsoutManagerTemplate, PiranhaManagementTemplate, SiteTemplateBase, StoredIQTemplate, StorwareTemplate, SynergySkyTemplate, UNISPHERETemplate, WatsonTemplate, XormonTemplate, XoruxTemplate, ZabbixTemplate, iDRACTemplate

disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

text_column1 = TextColumn("{task.fields[taskid]}", table_column=Column(ratio=1), style= "bold")

progress = Progress(
    text_column1, refresh_per_second= 1)

overall_progress = Progress(
    TimeElapsedColumn(), BarColumn(), TextColumn("{task.completed}/{task.total}")
)
overall_task_id = overall_progress.add_task("", start=False)

progress_group = Group(
    Panel(progress, title="URL Check", expand=False),
    overall_progress,
)

# Locks for file writing
error_lock = threading.Lock()
valid_lock = threading.Lock()
valid_url_lock = threading.Lock()
valid_template_lock = threading.Lock()
known_bads_lock = threading.Lock()
manual_lock = threading.Lock()
_401_lock = threading.Lock()
_valid_url_lock = threading.Lock()
comment_lock = threading.Lock()
no_template_lock = threading.Lock()

NV_VALID_URL = "nv-url-valid-url.txt"
NV_SUCCESS = "nv-url-success.txt"
NV_NOT_VALID = "nv-url-no-valid.txt"
NV_NO_TEMPLATE = "nv-url-no-template.txt"
NV_ERROR = "nv-url-error.txt"
NV_MANUAL = "nv-url-manual.txt"
NV_BAD = "nv-url-known-bad.txt"
NV_VERSION = "nv-url-version.txt"
NV_401 = "nv-url-401-basic.txt"
NV_COMMENTS = "nv-url-comments.txt"
REQUESTS_TIMEOUT = 15

chatgpt_admin_paths = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/adminpanel",
    "/admin_area",
    "/admincp",
    "/admin-console",
    "/admin/login.php",
    "/admin/index.php",
    "/login",
    "/signin",
    "/signin.php",
    "/user",
    "/user/login",
    "/account",
    "/accounts",
    "/auth",
    "/authenticate",
    "/session",
    "/dashboard",
    "/dashboard/login",
    "/controlpanel",
    "/control-panel",
    "/cpanel",
    "/manager",
    "/manage",
    "/backend",
    "/backend/login",
    "/backend-admin",
    "/portal",
    "/portal/login",
    "/console",
    "/system",
    "/system-admin",
    "/webadmin",
    "/adm",
    "/moderator",
    "/moderation",
    "/root",
    "/panel",
    "/siteadmin",
    "/site-admin",
    "/admin_area/login",
    "/administrator/index.php",
    "/user/register",
    "/register",
    "/signup",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-content",
    "/wordpress/wp-admin",
    "/wp/wp-admin",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/dbadmin",
    "/database",
    "/mysql",
    "/sql",
    "/webmail",
    "/roundcube",
    "/webmail/login",
    "/owa",
    "/exchange",
    "/autodiscover",
    "/joomla/administrator",
    "/administrator/components",
    "/drupal/user/login",
    "/user/login",
    "/admincp.php",
    "/panel.php",
    "/manage.php",
    "/adminconsole",
    "/auth/login",
    "/sso",
    "/saml",
    "/oauth",
    "/app",
    "/apps",
    "/service",
    "/services",
    "/api",
    "/api/v1",
    "/api/v2",
    "/rest",
    "/restapi",
    "/swagger",
    "/swagger-ui",
    "/docs",
    "/documentation",
    "/uploads",
    "/backup",
    "/backups",
    "/old",
    "/private",
    "/secure",
    "/adminka",
    "/management",
]

urls_to_try = [
    "/auth/admin/master/console",
    "/admin",
    "/trust",
    "/console",
    "/management",
    "/em",
    "/sal",
    "/analyst",
    "/mm",
    "/documents",
    "/tm",
    "/trace",
    "/ping",
    "/metrics",
    "/va",
    "/dms",
    "/workspace",
    "/initial",
    "/features",
    "/version",
    "/v2",
    "/manager",
    "/export",
    "/RM",
    "/health",
    "/authenticate",
    "/auth",
    "/provisioning",
    "/api",
    "/request",
    "/notices",
    "/captcha",
    "/logon",
    "/login",
    "/mail",
    "/sms",
    "/jsp",
    "/home",
    "/download",
    "/stats",
    "/commands",
    "/conf",
    "/logs/",
    "/static",
    "/jenkins",
    "/report",
    "/reports",
    "/wb",
    "/zabbix",
    "/i",
    ]

def extract_version(url, response):
    # response = requests.get(url, allow_redirects=True, verify=False, timeout=15)
    try:
        if response.headers["Server"].startswith("Jetty"):
            with valid_lock:
                with open(NV_VERSION, "a") as file:
                    file.write(f"{url} => {response.headers['Server']}\n")
            return True
    except:pass
    try:
        if '"couchdb":"Welcome"' in response.text and '"couchbase":' in response.text:
            rrr = re.search(r'"couchbase":"(.*)"', response.text, flags=re.IGNORECASE)
            if rrr:
                v = rrr.group(1)
                with valid_lock:
                    with open(NV_VERSION, "a") as file:
                        file.write(f"{url} => Couchbase {v}\n")
                return True
    except:pass
    try:
        if "/administrator" in response.text:
            response = requests.get(url + "/administrator", allow_redirects=True, verify=False, timeout=15)
            rrr = re.search(r'<span class="loginversionText" id="VersionInfo">(.*)', response.text, flags=re.IGNORECASE)
            if rrr:
                v = rrr.group(1)
                with valid_lock:
                    with open(NV_VERSION, "a") as file:
                        file.write(f"{url} => Informatica {v}\n")
                return True
    except:pass
    try:
        if "Oracle APEX Version" in response.text:
            rrr = re.search(r'Oracle APEX Version: (.*)', response.text, flags=re.IGNORECASE)
            if rrr:
                v = rrr.group(1)
                with valid_lock:
                    with open(NV_VERSION, "a") as file:
                        file.write(f"{url} => Oracle APEX Version {v}\n")
                return True
    except:pass
    return False



def check_if_loginpage_exists(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        input_fields = soup.find_all('input')
        has_password = any(field.get('type') == 'password' for field in input_fields) # type: ignore
        if has_password: return True
        return False
    except: return False

def check_if_known_bad_non_login(response: requests.Response):
    pass

def check_if_known_Bad(response: requests.Response):
    for header, value in response.headers.items():
        if "ClickHouse" in header: return "ClickHouse"
    if "Dynatrace Managed" in response.text:
        return "Dynatrace Managed"
    if "ExchangeService Service" in response.text:
        return "ExchangeService Service"
    if "This is a Windows© Communication Foundation service" in response.text:
        return "Windows© Communication Foundation service"
    if "Node Exporter" in response.text:
        return "Node Exporter"
    if "Humio bulk ingest endpoint" in response.text:
        return "Humio bulk ingest endpoint"
    if "Edison Forever!" in response.text:
        return "Edison Forever"
    if "Outlook" in response.text:
        return "Outlook"
    if "Web Tools" and "Element Manager" in response.text:
        return "Broadcom Web Tools Element Manager"
    if "<title>Nessus</title>" in response.text:
        return "Nessus Scanner"
    if "SOAP Plugin - Source Node Status" in response.text:
        return "SOAP Plugin - Source Node Status"
    if "Welcome to VMware Aria Operations" in response.text:
        return "Welcome to VMware Aria Operations"
    if "PaperCut Software" and "login-illo" in response.text:
        return "PaperCut MobilityPrint"
    if "OpenManage" in response.text:
        return "OpenManage"
    if "XenServer 7" in response.text:
        return "Citrix XenServer 7"
    if "TE-9-Login-Header.png" in response.text:
        return "Tripwire Enterprise 9"
    if "SSL Visibility Appliance" in response.text:
        return "Symantec SSL Visibility"
    if "IIS Windows Server" in response.text:
        return "IIS Windows Server"
    if "Unigy Management System" in response.text or "Unigy(TM) Management System" in response.text:
        return "Unigy Management System"
    if "STREAMS MESSAGING MANAGER" in response.text:
        return "Streams Messaging Manager"
    if "Aangine Automated Portfolio Planning" in response.text:
        return "Aangine Automated Portfolio Planning"
    if "UCMDB Server" in response.text:
        return "UCMDB Server"
    if "WCFDocumentControl Service" in response.text:
        return "WCFDocumentControl Service"
    if "Proofpoint Protection Server" in response.text:
        return "Proofpoint Protection Server"
    if "Isilon InsightIQ" in response.text:
        return "Isilon InsightIQ"
    if "NiFi" in response.text:
        return "NiFi"
    if "HiveServer2" in response.text:
        return "HiveServer2"
    if "Argo CD" in response.text:
        return "Argo CD"
    if "Veritas Data Insight" in response.text:
        return "Veritas Data Insight"
    if "Structured Data Manager" in response.text:
        return "Structured Data Manager"
    if "Micro Focus Robotic Process Automation" in response.text:
        return "Micro Focus Robotic Process Automation"
    if "DEF Web Admin Tool" in response.text:
        return "DEF Web Admin Tool"
    if "<title>DPA</title>" in response.text:
        return "Data Protection Advisor"
    if "Proxmox Datacenter Manager" in response.text:
        return "Proxmox Datacenter Manager"
    if "<title>SAP XSEngine</title>" in response.text:
        return "SAP XSEngine"
    if "<title>ManageEngine ServiceDesk Plus</title>" in response.text:
        return "ManageEngine ServiceDesk Plus"
    if "<title>RecoverPoint for VMs Plugin Server</title>" in response.text:
        return "RecoverPoint for VMs Plugin Server"
    if "<title>Coriolis</title>" in response.text:
        return "Coriolis"
    if "data-netbox-version" in response.text:
        return "Netbox"
    if "<title>WS server test page</title>" in response.text:
        return "WS server test page"
    if "fitalimicon.png" in response.text:
        return "FIT ALIM"
    if "Highest contiguous completed opid" in response.text:
        return "Cerebro Metrics"
    if "LibreNMS" in response.text:
        return "LibreNMS"
    if "VMware vSphere is virtual infrastructure software for partitioning" in response.text:
        return "Vmware vSphere Welcome Page"
    if "<title>Swagger UI</title>" in response.text: # No login
        return "Swagger UI"
    if "<title>Kubernetes Dashboard</title>" in response.text: # No default password
        return "Kubernetes Dashboard"
    if "<title>IBM Tivoli Monitoring Service Index</title>" in response.text: # No login
        return "IBM Tivoli Monitoring Service Index"
    if "<title>Finesse</title>" in response.text: # No default password
        return "Cisco Finesse" 
    if "<title>RMF Data Portal</title>" in response.text: # No login
        return "RMF Data Portal"
    if "<title>Cisco Meeting Server web app</title>" in response.text: # No default password
        return "Cisco Meeting Server web app"
    if "<title>WebSphere Liberty" in response.text: # No default password
        return "WebSphere Liberty"
    if "<title>Headlamp Debug Server</title>" in response.text: # No login
        return "Headlamp Debug Server"
    if "<title>Ivanti System Manager: Sign In</title>" in response.text: # No default password
        return "Ivanti System Manager"
    if "Couchbase Console - FICO Edition</title>" in response.text: # No default password
        return "Couchbase Console - FICO Edition"
    if "<title>Cisco Unified Intelligence Center</title>" in response.text: # No default password
        return "Cisco Unified Intelligence Center"
    if "<title>Log In - Confluence</title>" in response.text: # No default password
        return "Confluence"
    if "<title>Login - AppViewX</title>" in response.text: # No default password
        return "AppViewX"
    if "IA:IM: Login" in response.text: # No default password
        return "IBM Automation Infrastructure Management"
    if "<title>VMware Skyline Health Diagnostics</title>" in response.text:
        return "VMware Skyline Health Diagnostics"
    if "<title>Wowza Streaming Engine Manager</title>" in response.text:
        return "Wowza Streaming Engine Manager"
    if "<title>Qlik NPrinting</title>" in response.text:
        return "Qlik NPrinting"
    if "<title>Identity Service Management</title>" in response.text:
        return "Identity Service Management"
    if "cuicui" in response.text: # No default password
        return "Cisco Unified Intelligence Center"
    if "Identity Services Engine" in response.text:
        return "Cisco Identity Services Engine" # No default password
    if "Cisco Virtualized Voice Browser" in response.text:
        return "Cisco Virtualized Voice Browser Portal" # No default password no login page
    if "Cisco Unified Communications Manager" in response.text:
        return "Cisco Unified Communications Manager" # No default password no login page
    if "URL=/verba/" in response.text:
        return "VERINT Verba" # No default password
    if "Cisco Unified Communications Manager" in response.text or "Cisco Unified Communications Self Care Portal" in response.text:
        return "Cisco Unified Communications Manager/Self Care Portal Portal" # No default password no login page
    if "<title>RSA Security Analytics Login</title>" in response.text:
        return "RSA Security Analytics" # No default password
    if "FortiWeb" in response.text:
        return "FortiWeb" # No default password
    if "You Know, for Search" in response.text:
        return "Elastic cluster version endpoint" # No login
    if "Installed Applications" in response.text and "Cisco Systems logo" in response.text:
        return "Cisco generic portal" # No login
    if "ephemeral_id" in response.text and "username" in response.text and "pipeline" in response.text:
        return "Generic logstash version portal" # No login
    if "/core/console/console.html" in response.url:
        return "Dell OpenManage Enterprise" # No login
    if "Serv-U FTP Server" in response.text:
        return "Serv-U FTP Server" # No default password
    if "Please return to Webex Control Hub" in response.text:
        return "Cisco Webex" # No default password
    if "window['nprintingVersion']" in response.text and "window['npProject'] = \"newsstand\"":
        return "NPRinting NewsStand" # No default password
    if "NodeManager information" in response.text and "hadoop" in response.text:
        return "hadoop" # No login page
    if "it works!" in response.text.lower():
        return "it works!" # No login page
    if "truenas_core_logomark" in response.text.lower():
        return "TrueNAS" # No default password
    if "strapi" in response.text.lower():
        return "Strapi" # No default password
    if " <title>Communication Manager</title>" in response.text:
        return "Crane Communication Manager" # No default password
    if "crane-cdp.svg" in response.text and "<title>Loyalty - Login</title>":
        return "Crane CDP" # No default password
    if '<title ng-bind="mnTitle">Couchbase Server</title>' in response.text:
        return "Couchbase Server" # No default password
    if "<title>Business Performance Index - BPI</title>" in response.text:
        return "Crane BPI" # No default password
    if "<title>Oracle HTTP Server" in response.text:
        return "Oracle HTTP Server Homepage" # No login
    if "Prometheus Time Series Collection and Processing Server" in response.text:
        return "Prometheus Time Series Collection and Processing Server" # No login
    if "If you're seeing this, you've successfully installed Tomcat. Congratulations!" in response.text:
        return "Apache Tomcat Default homepage" # No login
    if "<title>Eureka</title>" in response.text and "<h1>System Status</h1>" in response.text:
        return "Eureka" # No login
    if "<title>Test Page for the Nginx HTTP Server on" in response.text:
        return "Test Page for the Nginx HTTP Server" # No login 
    if "<title>Wazuh</title>" in response.text:
        return "Wazuh" # No default password
    if "<title>Login | crane CGO</title>" in response.text:
        return "Crane CGO" # No default password
    if "<title>Portainer</title>" in response.text:
        return "Portainer" # No default password
    if "HELP jvm_info VM version info" in response.text:
        return "jvm debug" # No login
    if "<title>Log in | Django site admin</title>" in response.text:
        return "Django administration" # No default password
    if '<font color="blue">new </font><font color="black">SALicInterfaceClient</font>' in response.text:
        return "SALicInterfaceClient" # No login
    if "<title> Dynamic Workload Console </title>" in response.text:
        return "IBM Workload Scheduler" # No default password
    if "<title>DMS Spy</title>" in response.text:
        return "DMS Spy" # No default password
    if "<title>Oracle Enterprise Performance Management System Workspace, Fusion Edition</title>" in response.text:
        return "Oracle Enterprise Performance Management System Workspace, Fusion Edition" # No default password
    if '<font color="teal">WCFCommunicationInitialMetadataServiceClient</font>' in response.text:
        return "WCFCommunicationInitialMetadataServiceClient" # No login page
    if "<title>cAdvisor" in response.text:
        return "cAdvisor" # No login page
    if "<title>Graylog Web Interface</title>" in response.text:
        return "Graylog Web Interface" # No default password
    if '"NAME":"CentOS Linux","ID":"centos"' in response.text:
        return "CentOS Web Interface" # No default password
    if '{"couchdb":"Welcome"}' in response.text:
        return "CouchDB Welcome"

def check_if_manual(response):
    if "Sign in to RStudio" in response:
        return "RSTUDIO => rstudio:rstudio"
    if "Sign in to Posit Workbench" in response:
        return "POSIT WORKBENCH => rstudio:rstudio"
    if "GetDocLink.ashx?link=logon_troubleshooting" in response:
        return "Xperience => administrator:(blank)"
    if "Enable it to login into Central server" in response:
        return "Endpoint Central => admin:admin"
    if "ecs-loader" in response:
        return "DELL EMC ECS => root:ChangeMe emcsecurity:ChangeMe"
    if "<title>Allegro Packets Network Multimeter - Login</title>" in response:
        return "Allegro Packets Network Multimeter => admin:allegro"
    if "<title>Virtual Appliance Management Infrastructure</title>" in response:
        return "Avamar => root:avam@r"
    return None

def find_login(response):
    if "SAS Web Application Server" in response:
        return "/SASLogon/login"
    if "URL='/ui'" in response:
        return "/ui/#/login"
    return None

def is_login_page(response):
    soup = BeautifulSoup(response.text, "html.parser")
    password_input = soup.find("input", {"type": "password"})
    submit_button = soup.find("button", {"type": "submit"}) or soup.find("input", {"type": "submit"})
    if password_input and submit_button:
        return True
    return False

def real_check(url, response, templates, hostname):
    bad = check_if_known_bad_non_login(response)
    if bad:
        with known_bads_lock:
            with open(NV_BAD, "a") as file:
                file.write(f"{url}{f' | {hostname}' if hostname else ''} => {bad}\n")
        return
    is_login = is_login_page(response)

    # If it is login page, we check if its known bad
    if is_login:
        bad = check_if_known_Bad(response)
        if bad:
            with known_bads_lock:
                with open(NV_BAD, "a") as file:
                    file.write(f"{url}{f' | {hostname}' if hostname else ''} => {bad}\n")
            return
        # If it is not bad, then we check if it requires manual review
        manual = check_if_manual(response.text)
        if manual:
            with manual_lock:
                with open(NV_MANUAL, "a") as file:
                    file.write(f"{url}{f' | {hostname}' if hostname else ''} => {manual}\n")
            return
        # NO AUTH
        if "Grafana" in response.text and "login" not in response.url:
            with valid_lock:
                with open(NV_SUCCESS, "a") as file:
                    file.write(f"{url} => GRAFANA NO AUTH\n")
            print(f"{url}{f' | {hostname}' if hostname else ''} => Grafana NO AUTH")
            return
        if "Loading Elastic" in response.text and "spaces/space_selector" in response.url:
            with valid_lock:
                with open(NV_SUCCESS, "a") as file:
                    file.write(f"{url} => ELASTIC NO AUTH\n")
            print(f"{url}{f' | {hostname}' if hostname else ''} => Elastic NO AUTH")
            return
        if "WebSphere Integrated Solutions Console" in response.text and "Password" not in response.text:
            with valid_lock:
                with open(NV_SUCCESS, "a") as file:
                    file.write(f"{url} => WebSphere Integrated Solutions Console NO AUTH\n")
            print(f"{url}{f' | {hostname}' if hostname else ''} => WebSphere Integrated Solutions Console NO AUTH")
            return

        for zz in templates:
            try:
                result: URL_STATUS = zz.check(url, response.text, False)
                if result == URL_STATUS.VALID:
                    return

            except TimeoutError as timeout:
                with error_lock:
                    with open(NV_ERROR, "a") as file:
                        file.write(f"{url}{f' | {hostname}' if hostname else ''} => Timeout\n")
                        return
            except Exception as e:
                with error_lock:
                    with open(NV_ERROR, "a") as file:
                        file.write(f"{url}{f' | {hostname}' if hostname else ''} => {e.__class__.__name__} {e}\n")
                        return
        with no_template_lock:
            with open(NV_NO_TEMPLATE, "a") as file:
                title = find_title(None, response.text)
                file.write(f"{url}{f' | {hostname}' if hostname else ''}{f' => {title}' if title else ''}\n")

# TO DO:
def find_title(url, response):
    soup = BeautifulSoup(response, 'html.parser')
    title_tag = soup.title
    if title_tag and title_tag.string:
        t = title_tag.string.strip()
        if t.startswith("BIG-IP"):
            return "BIG-IP"
        return title_tag.string.strip()
    


    if "/cgi/login.cgi" in response and "Insyde Software" in response:
        return "Veritas Remote Management"
    if "https://tomcat.apache.org" in response:
        return "Tomcat (No Version)"
    

    
    return ""

def extract_comment(response):
    soup = BeautifulSoup(response.text, "html.parser")

    # Find all HTML comments
    return [c.strip() for c in soup.find_all(string=lambda text: isinstance(text, Comment))] # type: ignore

def check_basic_auth(resp):
    """
    Check if a URL requires HTTP Basic Authentication.
    
    Returns:
        (requires_auth: bool)
    """
    try:
        if resp.status_code == 401:
            # Check for WWW-Authenticate header
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if www_auth:
                return True
        else:
            return False
    except Exception as e:
        return False

def authcheck(url, templates: list[type[SiteTemplateBase]], verbose, wasprocessed = False):
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    hostname = None

    templates2 = [zzz() for zzz in templates] # type: ignore

    try:
        response = requests.get(url, allow_redirects=True, headers=headers, verify=False, timeout=15)

        # We try to find dns of the ip
        try:
            pattern = r'https?://(.*):'
            match_hostname = re.match(pattern, url)
            if match_hostname:
                ip = match_hostname.group(1)

                hostname, _, _ = socket.gethostbyaddr(ip)
        except:pass

        # Find if there was a redirect thru meta tag
        match = re.search(r'<meta .*;URL=(.*)"\s*', response.text, re.IGNORECASE)
        if match:
            redirect_url = match.group(1)
            redirect_url = redirect_url.strip("'")
            redirect_url = redirect_url.strip("\"")
            redirect_url = redirect_url.strip(".")
            authcheck(url + redirect_url, templates, verbose, True)
            return

        if response.headers.get("Content-Length") == "0" or response.text.lower() == "ok" or response.text.lower() == "hello world!":
            with known_bads_lock:
                with open(NV_BAD, "a") as file:
                    file.write(f"{url}{f' | {hostname}' if hostname else ''} => Empty or 'OK'\n")
            return
        
        comments = extract_comment(response)
        with comment_lock:
            with open(NV_COMMENTS, "a") as file:
                file.write(f"{url}{f' | {hostname}' if hostname else ''}\n")
                for c in comments:
                    file.write(f"{c}\n")

        # We first check if there is any version on the page, if so we find it and return
        vv = extract_version(url, response)
        if vv: return

        # If we get 200 we first check if its bad before we check login, if it is not bad we try to look for a login page
        if response.status_code in [200]:
            bad = check_if_known_bad_non_login(response)
            if bad:
                with known_bads_lock:
                    with open(NV_BAD, "a") as file:
                        file.write(f"{url}{f' | {hostname}' if hostname else ''} => {bad}\n")
                return
            is_login = is_login_page(response)

            # If it is login page, we check if its known bad
            if is_login:
                real_check(url, response, templates2, hostname)
            else:
                # If there was no login page we try to enumerate common directories to find a login page
                for u in urls_to_try:
                    response = requests.get(url + u, allow_redirects=True, verify=False, timeout=REQUESTS_TIMEOUT)
                    if check_basic_auth(response):
                        with _401_lock:
                            with open(NV_401, "a") as file:
                                file.write(f"{url}{f' | {hostname}' if hostname else ''}\n")
                    if response.status_code in [200] and is_login_page(response):
                        real_check(url, response, templates2, hostname)
                        return
                    
        if response.status_code >= 400:
            if check_basic_auth(response):
                with _401_lock:
                    with open(NV_401, "a") as file:
                        file.write(f"{url}{f' | {hostname}' if hostname else ''}\n")
            if response.status_code in [404]:
                try:
                    for t in templates2:
                        if t.need404:
                            result: URL_STATUS = t.check(url, response.text, False)
                            if result == URL_STATUS.VALID:
                                return
                except Exception as e:
                    pass
            for u in urls_to_try:
                response = requests.get(url + u, allow_redirects=True, verify=False, timeout=15)
                if response.status_code in [200] and is_login_page(response):
                    real_check(url, response, templates2, hostname)
                    return

            if verbose:
                print(f"{url} => {response.status_code}")
            with error_lock:
                with open(NV_ERROR, "a") as file:
                    file.write(f"{url}{f' | {hostname}' if hostname else ''} => {response.status_code}\n")
            return

    except requests.exceptions.ConnectTimeout as e:
        with error_lock:
            with open(NV_ERROR, "a") as file:
                file.write(f"{url}{f' | {hostname}' if hostname else ''} => ConnectTimeout\n")
        return
    except requests.exceptions.ReadTimeout as e:
        with error_lock:
            with open(NV_ERROR, "a") as file:
                file.write(f"{url}{f' | {hostname}' if hostname else ''} => ReadTimeout\n")
        return
    except Exception as e:
        with error_lock:
            with open(NV_ERROR, "a") as file:
                file.write(f"{url}{f' | {hostname}' if hostname else ''} => {e.__class__.__name__} {e}\n")
        return
    
def start_authcheck(url, templates, task_id, verbose):
    progress.update(task_id, visible=True)
    progress.start_task(task_id)
    authcheck(url, templates, verbose, False)
    progress.remove_task(task_id)
    overall_progress.update(overall_task_id, advance=1)

def groupup(filename):
    # Dictionary to group URLs by title
    grouped_urls = defaultdict(list)

    # Read the file line by line
    try:
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines

                # Split the line into URL and title
                if " => " in line:
                    url, title = line.split(" => ", 1)
                    grouped_urls[title].append(url)
                else:
                    # URLs without a title go into a special "No Title" group
                    grouped_urls["No Title"].append(line)

        # Format the grouped URLs
        output_lines = []
        for title, urls in grouped_urls.items():
            output_lines.append(f"{title}:\n")
            output_lines.append("-----\n")
            output_lines.extend(f"{url}\n" for url in urls)
            output_lines.append("\n")  # Add a blank line between groups

        # Output to file or stdout

        try:
            with open(filename, "w") as output_file:
                output_file.writelines(output_lines)
            # print(f"Grouped URLs have been written to '{filename}'.")
        except Exception as e:
            print(f"Error writing to file '{filename}': {e}")
    except FileNotFoundError:
        pass


def main():
    parser = argparse.ArgumentParser(description="Website Default Credentials Authentication Checker")
    parser.add_argument("-t", default="urls.txt", help="Target URL/file to test.")
    parser.add_argument("--group-up", action="store_true", help="Groups up the output files if there was a problem on main function.")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use. (Default = 10)")
    parser.add_argument("--dns-ip", type=str, help="DNS ip to do reverse DNS lookup")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    args = parser.parse_args()

    templates: list[type[SiteTemplateBase]] = [
        ArisconnectTemplate, 
        FortigateTemplate,
        GrafanaTemplate,
        HighAvailabilityManagementTemplate,
        iDRACTemplate,
        IPECSIPPhoneTemplate,
        IRISIDICAMTemplate,
        LogparseTemplate,
        MyQTemplate,
        NetscalerConsoleTemplate,
        NexthinkConsoleTemplate,
        OpinnateTemplate,
        OracleLightsoutManagerTemplate,
        StoredIQTemplate,
        StorwareTemplate,
        SynergySkyTemplate,
        UNISPHERETemplate,
        WatsonTemplate,
        XormonTemplate,
        XoruxTemplate,
        ZabbixTemplate,
        FlexNetPublishTemplate,
        JHipsterRegistryManagementTemplate,
        IBMSoftwareAGTemplate,
        PiranhaManagementTemplate,
        FujitsuWebServerTemplate,
        ]

    if args.group_up:
        groupup(NV_ERROR)
        groupup(NV_BAD)
        groupup(NV_MANUAL)
        groupup(NV_NO_TEMPLATE)
        groupup(NV_NOT_VALID)
        groupup(NV_SUCCESS)
        groupup(NV_VERSION)
        return
    



    max_threads = args.threads


    # If given url is a file, read it line by line and run the templates on each line
    if os.path.isfile(args.t):
        with open(args.t, "r") as file:
            hosts = [line.strip() for line in file]  # Strip newline characters

        with Live(progress_group):
            overall_progress.update(overall_task_id, total=len(hosts))
            overall_progress.start_task(overall_task_id)
            with ThreadPoolExecutor(max_threads) as executor:
                for host in hosts:
                    task_id = progress.add_task("url", taskid=f"{host}", status="status", start=False)
                    progress.update(task_id, visible=False)
                    executor.submit(start_authcheck, host, templates, task_id, args.verbose)


        groupup(NV_ERROR)
        groupup(NV_BAD)
        groupup(NV_MANUAL)
        groupup(NV_NO_TEMPLATE)
        groupup(NV_NOT_VALID)
        groupup(NV_SUCCESS)
        groupup(NV_VERSION)

    # If given url is simply a website, run the templates on the website
    else:
        authcheck(args.target, templates, args.verbose)


if __name__ == "__main__":
    main()