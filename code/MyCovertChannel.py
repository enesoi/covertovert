import random
import time

from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, Raw, sniff
from scapy.layers.l2 import LLC


class MyCovertChannel(CovertChannelBase):
    """
    Implements a covert channel communication system.

    Notes:
        - You are not allowed to change the file name and class name.
        - You can edit the class in any way you want (e.g., adding helper functions).
        - The class must include `send` and `receive` methods, which trigger the covert channel.
    """

    def __init__(self):
        """
        Initializes the `MyCovertChannel` class.

        Notes:
            - You can edit this method to set up any required state or configurations.
        """
        pass

    def send(self, log_file_name, limit, dest_mac, source_mac):
        """
        Sends a covert message by encoding data into Ethernet packets.

        Steps:
            - Create a random binary message.
            - Encode each bit using the control (`ctrl`) field:
                * If bit is 1: `ctrl` ∈ [0, limit]
                * If bit is 0: `ctrl` ∈ (limit, 255]
            - Construct Ethernet/LLC packets using the specified source and destination MAC addresses.
            - Wait 50ms between each packet transmission.

        Parameters:
            log_file_name (str): Name of the log file to record the sent message.
            limit (int): Threshold value for splitting the control (`ctrl`) field.
            dest_mac (str): Destination MAC address for the Ethernet layer.
            source_mac (str): Source MAC address for the Ethernet layer.

        Returns:
            None
        """
        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name, min_length=16, max_length=16
        )

        eth_layer = Ether(dst=dest_mac, src=source_mac, type=0xAAAA)

        for bit in binary_message:
            if bit == "1":
                ctrl = random.randint(0, limit)
            elif bit == "0":
                ctrl = random.randint(limit + 1, 255)

            dsap = random.randint(0, 255)
            ssap = random.randint(0, 255)
            llc_layer = LLC(dsap=dsap, ssap=ssap, ctrl=ctrl)
            packet = eth_layer / llc_layer
            super().send(packet)
            time.sleep(0.05)

    def receive(self, log_file_name, limit):
        """
        Receives a covert message by decoding data from Ethernet packets.

        Steps:
            - Sniff packets with the specified Ethernet protocol.
            - Decode the `ctrl` field:
                * If `ctrl` > limit: decode as 0.
                * Otherwise, decode as 1.
            - Convert every 8 bits into a character and append to the received message.
            - Stop processing when a period (`"."`) is received.

        Parameters:
            log_file_name (str): Name of the log file to record the received message.
            limit (int): Threshold value for decoding the control (`ctrl`) field.

        Returns:
            None
        """
        received_msg = ""
        bits = ""
        bit_count = 0
        leave = False
        while True:
            packet = sniff(iface="eth0", filter="ether proto 0xaaaa", count=1)
            pkt = packet[0]
            llc = LLC(pkt[Raw].load)

            if llc.ctrl > limit:
                bits += "0"
            else:
                bits += "1"

            bit_count += 1

            if bit_count == 8:
                bit_count = 0
                ch = self.convert_eight_bits_to_character(bits)
                received_msg += ch
                bits = ""

                if ch == ".":
                    leave = True
                    break
            if leave:
                break
        self.log_message(received_msg, log_file_name)
