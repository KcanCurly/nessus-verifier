from pydoc import cli
import subprocess

import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import logging
import sys

import smpplib.gsm
import smpplib.client
import smpplib.consts

class SMPPExperimentalSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("experimental", "Experimental")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        # if you want to know what's happening
        logging.basicConfig(level='DEBUG')

        # Two parts, UCS2, SMS with UDH
        parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(u'Hello World\n'*10)

        results= get_default_context_execution2("SMPP Experimental", self.threads, hosts, self.single, parts=parts, encoding_flag=encoding_flag, msg_type_flag=msg_type_flag, timeout=self.timeout, errors=self.errors, verbose=self.verbose)


    @error_handler(["host"])
    def single(self, host, **kwargs):
        parts = kwargs.get("parts")
        encoding_flag = kwargs.get("encoding_flag")
        msg_type_flag = kwargs.get("msg_type_flag")

        client = smpplib.client.Client(host.ip, host.port, allow_unknown_opt_params=True)

        # Print when obtain message_id
        client.set_message_sent_handler(
            lambda pdu: sys.stdout.write('sent {} {}\n'.format(pdu.sequence, pdu.message_id)))
        client.set_message_received_handler(
            lambda pdu: sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id)))

        client.connect()
        client.bind_transceiver(system_id='login', password='secretsecret')

        #for part in parts:
        #    pdu = client.send_message(
        #        source_addr_ton=smpplib.consts.SMPP_TON_INTL,
        #        #source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
        #        # Make sure it is a byte string, not unicode:
        #        source_addr='SENDERPHONENUM',
#
        #        dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
        #        #dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
        #        # Make sure thease two params are byte strings, not unicode:
        #        destination_addr='PHONENUMBER',
        #        short_message=part,
#
        #        data_coding=encoding_flag,
        #        esm_class=msg_type_flag,
        #        registered_delivery=True,
        #    )
        #    print(pdu.sequence)
            
        # Enters a loop, waiting for incoming PDUs
        client.listen()
        # client.disconnect()

class SMPPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("smpp")
        self.register_subservice(SMPPExperimentalSubServiceClass())