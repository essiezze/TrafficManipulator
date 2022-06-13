# !/user/bin/env python
"""
An example function for launching adaptive DoS attacks.
"""

from replay_with_level import *

__author__ = "Zhien Zhang"
__email__ = "zhien.zhang@uqconnect.edu.au"


def multi_level_attack(dst_ip: str, dst_mac: str, iface: str, attack_traffic: list):
    re = Replay(attack_traffic)
    re.replay_with_ping(dst_ip, dst_mac, iface, rounds=3)
