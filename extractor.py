import argparse
import sys
import AfterImageExtractor.FEKitsune as Fe
from AfterImageExtractor.KitsuneTools import RunFE
import numpy as np
from scapy.all import *

if __name__ == "__main__":

    parse = argparse.ArgumentParser()

    parse.add_argument('-i', '--input_path', type=str, required=True, help="raw traffic (.pcap) path")
    parse.add_argument('-o', '--output_path', type=str, required=True, help="feature vectors (.npy) path")
    parse.add_argument('-l', '--limit', type=int, default=np.Inf, help="limit on the num of pkts stored in memory")
    parse.add_argument("-s",  '--split_output_size', type=int, default=None, help="split the outputs into files with "
                                                                                  "no more than the number of pkts")

    arg = parse.parse_args()
    pcap_file = arg.input_path

    feat_file = arg.output_path

    scapyin = rdpcap(pcap_file)

    FE = Fe.Kitsune(scapyin, arg.limit)
    feature, _ = RunFE(FE)

    print(np.asarray(feature).shape)
    np.save(feat_file,feature)

            
