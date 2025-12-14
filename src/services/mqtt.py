import i18n
from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("$SYS/#")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

class MQTTVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)

        nm = nmap.PortScanner()
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MQTT Version", self.threads, hosts, self.single, nm=nm, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name='AMQP'))
            
            for key, value in versions.items():
                extra, pure_version = key.rsplit(" ", 1)

                cpe = ""
                cves = []
                if "rabbitmq" in key.lower():
                    cpe = f"cpe:2.3:a:vmware:rabbitmq:{pure_version}"
                if cpe:
                    if self.should_print_cves:
                        cves = get_cves(cpe)
                if cves: 
                    self.print_output(f"{extra} {pure_version} ({", ".join(cves)}):")
                else:
                    self.print_output(f"{extra} {pure_version}:")

                for v in value:
                    self.print_output(f"    {v}")

            if self.should_print_latest_version:
                latest_versions = self.parent_service.get_latest_version()
                if latest_versions:
                    self.print_output(f"Latest version for {self.parent_service.eol_product_name}")
                    for version in latest_versions:
                        self.print_output(version)



    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        mqttc = mqtt.Client(CallbackAPIVersion.VERSION2)
        mqttc.on_connect = on_connect
        mqttc.on_message = on_message
        mqttc.username_pw_set("system", "manager")
        mqttc.connect(ip, int(port), 60)
        print(mqttc.is_connected())
        mqttc.disconnect()
        print(mqttc.is_connected())



class MQTTServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mqtt")
        self.register_subservice(MQTTVersionSubServiceClass())