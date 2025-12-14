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

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MQTT Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)



    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        mqttc = mqtt.Client(CallbackAPIVersion.VERSION2)
        mqttc.on_connect = on_connect
        mqttc.on_message = on_message
        print(1)
        mqttc.username_pw_set("system", "manager")
        print(2)
        mqttc.connect(ip, int(port), 60)
        print(3)
        mqttc.loop_start()
        print(4)
        print(mqttc.is_connected())
        print(5)
        mqttc.disconnect()
        print(6)
        mqttc.loop_stop()
        print(7)
        print(mqttc.is_connected())
        print(8)



class MQTTServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mqtt")
        self.register_subservice(MQTTVersionSubServiceClass())