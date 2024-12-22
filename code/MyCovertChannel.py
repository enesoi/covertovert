from scapy.all import sniff, Ether, Raw
from scapy.layers.l2 import LLC
import random
import time

from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, limit):
        """
        Steps:
        - Create a random binary message.
        - For each bit (limit parameter splits field value range into two):
            - If 1, ctrl <- [0,limit]
            - If 0, ctrl <- (limit,255]
        - Packet format: Ethernet / LLC
        - dsap and ssap are randomly generated.
        - dst and src are written according to how Docker generates MAC addresses (basically 02:42:[IP addr. in hexadecimal format]) 
        
        Current implementation requires we wait 50ms for each bit sent.
        current capacity: 6.4 bits per second
        """
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        print("Our message is : {}".format(binary_message))
        
        eth_layer = Ether(dst="02:42:ab:12:00:03", src="02:42:ab:12:00:02", type=0xaaaa)
        for bit in binary_message:
            if bit == "1":
                ctrl = random.randint(0,limit)

            elif bit == "0":
                ctrl = random.randint(limit + 1, 255)
            
            dsap = random.randint(0,255)
            ssap = random.randint(0,255)
            llc_layer = LLC(dsap=dsap, ssap=ssap, ctrl=ctrl)
            packet = eth_layer / llc_layer            
            super().send(packet)   
            time.sleep(0.05)     
                

        
    def receive(self, log_file_name, limit):
        """
        Steps:
        - Sniff each packet one by one.
          (the reason for [::2]): Received packets include duplicates so we skip one of each. 
        - For some reason, scapy won't recognize LLC layer, instead shows that layer as Raw.
          For this reason we first convert it to LLC from Raw values.
        - If ctrl above limit, decode as 0, else 1
        - At each 8th packet, convert it to char and append to received_msg
        - Do until "." is read
        """
        
        received_msg = ""
        bits = ""
        bit_count = 0
        leave = False
        while True:
            packet = sniff(iface="eth0", filter= "ether proto 0xaaaa", count=1)
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
                # print("received message = {}".format(received_msg))
                    
                if ch == ".":
                    leave = True
                    break 
            if leave:
                break
        self.log_message(received_msg, log_file_name)
