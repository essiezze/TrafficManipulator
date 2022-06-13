# !/user/bin/env python
"""
Extract features from the raw traffic flow and write into small sub-files.
"""

import AfterImageExtractor.FEKitsune as Fe
from scapy.all import *
from AfterImageExtractor.KitsuneTools import RunFE

if __name__ == "__main__":
    pcap_path = "/Users/essiezhang/Desktop/temp/2022-4-27/singlelevel.pcap"
    feat_output_path = "/Users/essiezhang/Desktop/temp/2022-4-27/single-level/extracted/single-level.npy"
    MAX_HOST = 200000
    MAX_SESSION = 200000
    ROWS_PER_FILE = 20000

    scapyin = PcapReader(pcap_path)
    FE = Fe.Kitsune(scapyin, max_host=MAX_HOST, max_sessions=MAX_SESSION)
    RunFE(FE, output_file=feat_output_path, split_size=ROWS_PER_FILE)
