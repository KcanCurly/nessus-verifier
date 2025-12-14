from time import sleep
import i18n
from src.utilities.utilities import error_handler, generate_random_string, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    return
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("$SYS/#")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    return
    print(msg.topic+" "+str(msg.payload))

class MQTTBruteforceSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("bruteforce", "Bruteforce for valid credentials")

class MQTTSSLSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("ssl", "Checks for SSL/TLS")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("MQTT SSL Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output(i18n.t('main.non_tls_connection_accepted', name='MQTT'))
            for r in results:
                self.print_output(f"    {r}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")


        try:
            mqttc = mqtt.Client(CallbackAPIVersion.VERSION2)
            mqttc.on_connect = on_connect
            mqttc.on_message = on_message

            mqttc.username_pw_set(username, password)
            mqttc.connect(host.ip, int(host.port), 60)
            
            mqttc.loop_start()
            sleep(0.5)
            s = mqttc.is_connected()
            mqttc.disconnect()
            mqttc.loop_stop()
            sleep(0.5)

            return f"{host.ip}:{host.port}"

        except Exception as e:
            print("Error", e)

class MQTTDefaultCredsSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("defaultcreds", "Checks for default credentials")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("MQTT Random Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username=generate_random_string(), password=generate_random_string())

        if results:
            self.print_output(i18n.t('main.activemq_unauth_access', name='MQTT'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

        results = get_default_context_execution2("MQTT Anonymous Access Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, anonymous=True)

        if results:
            self.print_output(i18n.t('main.anonymous_creds_title', name='MQTT'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

        results = get_default_context_execution2("MQTT Default Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="system", password="manager")

        if results:
            self.print_output(i18n.t('main.default_creds_title', name='MQTT'))
            for r in results:
                self.print_output(f"    {r}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")
        anonymous = kwargs.get("anonymous", False)
        s = False
        try:
            mqttc = mqtt.Client(CallbackAPIVersion.VERSION2)
            mqttc.on_connect = on_connect
            mqttc.on_message = on_message
            if not anonymous:
                mqttc.username_pw_set(username, password)
            mqttc.tls_set()
            mqttc.connect(host.ip, int(host.port), 60)
            
            mqttc.loop_start()
            sleep(0.5)
            s = mqttc.is_connected()
            mqttc.disconnect()
            mqttc.loop_stop()
            sleep(0.5)
            if s:
                return f"{host.ip}:{host.port}"

        except Exception as e:
            print("Error", e)


class MQTTServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mqtt")
        self.register_subservice(MQTTDefaultCredsSubServiceClass())
        self.register_subservice(MQTTSSLSubServiceClass())