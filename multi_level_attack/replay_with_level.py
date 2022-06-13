# !/user/bin/env python
"""
Replay manipulated attacks
"""

from time import time, sleep
from scapy.all import *
from threading import Thread


__author__ = "Zhien Zhang"
__email__ = "zhien.zhang@uqconnect.edu.au"


class Replay:
    def __init__(self, attack_traffic: list, timeout=1, health_check_interv=30):
        """
        :param attack_traffic: a list of paths to attack traffic in pcap format. The paths are orders by intensity,
        from low to high.
        :param timeout: the timeout for ping in seconds
        :param health_check_interv: the time interval for checking the target network condition in seconds
        """
        self.attack_traffic = attack_traffic
        self.num_of_levels = len(self.attack_traffic)
        self.current_idx = int(self.num_of_levels / 2)
        self.timeout = timeout
        self.health_check_iterv = health_check_interv
        self.health_check_thread = None
        self.last_health_check_result = None
        self.health_check_record = {}
        self.health_check_count = 0
        self.strategies = []
        self.health_check_record_this_round = []

    def replay_with_ping(self, tgt_ip: str, tgt_mac: str, iface: str, rounds=4):
        for i in range(rounds):
            print(f"Starting round {i}")
            next_round = self.replay_with_ping_single_round(tgt_ip, tgt_mac, iface)
            self.change_traffic(next_round)
            print(f"Round {i} finished")

    def replay_with_ping_single_round(self, tgt_ip: str, tgt_mac: str, iface="vboxnet0"):
        reader = PcapReader(self.attack_traffic[self.current_idx])
        self.strategies.append(self.attack_traffic[self.current_idx])
        reached_end = False
        last_time = None
        last_pkt_timestamp = None
        next_round = None
        last_check = time.time()

        while not reached_end:
            try:
                pkt = reader.next()
                self.change_dst(pkt, tgt_ip, tgt_mac)
                timestamp = pkt.time

                if last_pkt_timestamp is None:
                    interval = 0
                else:
                    interval = timestamp - last_pkt_timestamp

                while last_time is not None and time.time() - last_time < interval:
                    # wait
                    pass

                sendp(pkt, iface=iface, verbose=False)
            except StopIteration as e:
                reached_end = True

            # health check
            if time.time() - last_check >= self.health_check_iterv:
                self.health_check(tgt_ip)
                last_check = time.time()

            # is a health check thread has been created and finished
            if self.health_check_thread is not None and not self.health_check_thread.is_alive():
                self.health_check_thread.join()
                self.health_check_thread = None

                # get the average RTT of this round
                avg_rtt = sum(self.health_check_record_this_round) / len(self.health_check_record_this_round)
                if -1 in self.health_check_record_this_round or avg_rtt > self.timeout:
                    next_round = "lower"
                else:
                    next_round = "higher"

                self.health_check_record_this_round = []

        return next_round

    @staticmethod
    def change_dst(pkt, new_ip: str, new_mac: str):
        if IP in pkt:
            pkt[IP].dst = new_ip
            del pkt[IP].chksum
        if Ether in pkt:
            pkt[Ether].dst = new_mac
        return pkt

    def health_check(self, tgt_ip: str):
        self.health_check_thread = Thread(target=self.health_check_helper, args=(tgt_ip,))
        self.health_check_thread.start()

    def health_check_helper(self, tgt_addr: str):
        pkt = IP(dst=tgt_addr)/ICMP()
        response = sr(pkt, timeout=self.timeout)
        if len(response[0]) == 0:
            result = -1
        else:
            result = response[0][0].answer.time - pkt.time

        self.health_check_count += 1
        self.health_check_record[self.health_check_count] = result
        self.last_health_check_result = result
        self.health_check_record_this_round.append(result)

    def change_traffic(self, intensity: str):
        """
        Change the attack traffic used.

        :param intensity: either "lower" or "higher" for the intensity of the next round
        """
        if intensity == "lower" and self.current_idx != 0:
            self.current_idx = self.current_idx - 1
        elif intensity == "higher" and self.current_idx != len(self.attack_traffic) - 1:
            self.current_idx = self.current_idx + 1
