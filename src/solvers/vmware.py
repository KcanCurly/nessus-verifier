from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler, get_cves
import re
import subprocess
import requests
from bs4 import BeautifulSoup

def fetch_vcenter_mapping():
    url = "https://knowledge.broadcom.com/external/article/326316/build-numbers-and-versions-of-vmware-vce.html"
    r = requests.get(url, verify=False)
    soup = BeautifulSoup(r.text, "html.parser")
    mapping = {}
    # Loop through table rows
    catch_update_text = False
    catch_build_text_1 = False
    catch_build_text_2 = False
    catch_build_text_3 = False
    last_update_text = ""
    for row in soup.find_all("tr"):
        # print(row)
        tds =row.find_all("td")
        for td in tds:
            value = td.text
            if catch_build_text_3:
                mapping[value] = last_update_text
                catch_build_text_3 = False
                catch_build_text_2 = False
                catch_build_text_1 = False
                continue
            if catch_build_text_2:
                catch_build_text_3 = True
                continue
            if catch_build_text_1:
                catch_build_text_2 = True
                continue

            if "vcenter server 7" in value.lower() or "vcenter server 8" in value.lower():
                value = value.replace("vCenter Server 8.0.0", "").strip()
                value = value.replace("vCenter Server 7.0.0", "").strip()
                value = value.replace("vCenter Server 8.0", "").strip()
                value = value.replace("vCenter Server 7.0", "").strip()
                if "Update" in value:
                    value = value.replace(" ", "")
                last_update_text = value
                catch_build_text_1 = True

    return mapping

def fetch_esxi_mapping():
    url = "https://knowledge.broadcom.com/external/article/316595/build-numbers-and-versions-of-vmware-esx.html"
    r = requests.get(url, verify=False)
    soup = BeautifulSoup(r.text, "html.parser")
    mapping = {}
    # Loop through table rows
    catch_update_text = False
    catch_build_text = False
    catch_build_text_primed = False
    last_update_text = ""
    for row in soup.find_all("tr"):
        # print(row)
        tds =row.find_all("td")
        for td in tds:
            value = td.text
            if catch_build_text_primed:
                mapping[value] = last_update_text
                catch_build_text = False
                catch_build_text_primed = False
                continue
            if catch_build_text:
                catch_build_text_primed = True
                continue
            if catch_update_text:
                value = value.replace("ESXi 8.0", "").strip()
                value = value.replace("ESXi 7.0", "").strip()
                if "Update" in value:
                    value = value.replace(" ", "_")
                last_update_text = value
                catch_update_text = False
                catch_build_text = True
                continue
            if "esxi 7" in value.lower() or "esxi 8" in value.lower():
                catch_update_text = True

    return mapping

class VmwareSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("VMWare Product Versions", 13)
        self.output_filename_for_all = "old-vmware.txt"
        self.output_png_for_action = "old-vmware.png"
        self.action_title = "OldVmware"
        
    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        
        esxi_map = fetch_esxi_mapping()
        vcenter_map = fetch_vcenter_mapping()

        r = r"\[\+\] (.*) - Identified (.*)"
        versions = {}

        result = ", ".join(h.ip for h in self.hosts)
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS {result}; set ConnectTimeout {args.timeout}; set THREADS {args.threads}; run; exit"]
        try:
            result = subprocess.run(command, text=True, capture_output=True)
            
            matches = re.findall(r, result.stdout)
            for m in matches:
                if m[1] not in versions:
                    versions[m[1]] = []
                versions[m[1]].append(f"{m[0]}")
                    
        except Exception as e:
            self._print_exception(e)

        
        if versions:
            self.print_output("Detected Vmware Versions:")
            for key, value in versions.items():
                cves = []
                
                if "esxi" in key.lower(): 
                    r = r"VMware ESXi (\d+\.\d+\.\d+) build-(\d+)"
                    m = re.search(r, key)
                    if m:
                        version = m.group(1)
                        build = m.group(2)
                        
                        if version.startswith("5") or version.startswith("6"):
                            cves = ["EOL"]
                        else:
                            vv = ""
                            if version.startswith("7"):
                                vv = "7.0"
                            if version.startswith("8"):
                                vv = "8.0"
                            u = esxi_map[build]
                            cves = get_cves(f"cpe:2.3:o:vmware:esxi:{vv}:{u}")
                elif "vcenter server" in key.lower(): 
                    r = r"VMware vCenter Server (\d+\.\d+\.\d+) build-(\d+)"
                    m = re.search(r, key)
                    if m: 
                        version = m.group(1)
                        build = m.group(2)
                        if version.startswith("6") or version.startswith("5"):
                            cves = ["EOL"]
                        else:
                            vv = ""
                            if version.startswith("7"):
                                vv = "7.0"
                            if version.startswith("8"):
                                vv = "8.0"
                            u = vcenter_map[build].lower()
                            print(u)
                            cves = get_cves(f"cpe:2.3:a:vmware:vcenter_server:{vv}:{u}")
                        
                if cves: 
                    self.print_output(f"{key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"{" " * 4}{v}")
        self.create_windowcatcher_action()

