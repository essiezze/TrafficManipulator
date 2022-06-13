"""
The entry point to the traffic manipulator
"""

import numpy as np
import pickle as pkl
from scapy.all import *
import argparse
from manipulator import Manipulator

# default PSO parameters
MAX_ITER, PARTICLE_NUM, LOCAL_GRP_SIZE = 3, 6, 3
# max_iter,particle_num,local_grp_size = 4,8,4
# max_iter,particle_num,local_grp_size = 5,10,5
# max_iter,particle_num,local_grp_size = 3,10,5

# default particle parameters
W, C1, C2 = 0.7298, 1.49618, 1.49618

# default manipulator parameters
GRP_SIZE = 100
MIN_TIME_EXTEND = 3.
MAX_TIME_EXTEND = 6.
MAX_CFT_PKT = 1
MAX_CRAFTED_PKT_PROB = 0.01

# default init pcap file
INIT_PCAP = 'example/init.pcap'

# default statistic output path
STAT_OUTPUT_PATH = './example/statistics.pkl'


def set_default_params(manipulator: Manipulator):
    manipulator.change_particle_params(w=W, c1=C1, c2=C2)
    manipulator.change_pso_params(max_iter=MAX_ITER,
                                  particle_num=PARTICLE_NUM,
                                  grp_size=LOCAL_GRP_SIZE)
    # default settings
    manipulator.change_manipulator_params(grp_size=GRP_SIZE,
                                          min_time_extend=MIN_TIME_EXTEND,
                                          max_time_extend=MAX_TIME_EXTEND,
                                          max_cft_pkt=MAX_CFT_PKT,
                                          max_crafted_pkt_prob=MAX_CRAFTED_PKT_PROB)


def manip_with_default_params(mal_pcap: str, mimic_set: str, normalizer: str,
                              init_pcap=INIT_PCAP, stat_output=STAT_OUTPUT_PATH):
    m = Manipulator(mal_pcap, mimic_set, normalizer, init_pcap)
    set_default_params(m)
    # m.save_configurations('./configurations.txt')

    # tmp_pcap_file = "_crafted.pcap"
    # m.process(tmp_pcap_file, arg.sta_file, limit=20)

    m.process(stat_output, limit=np.Inf, heuristic=False)


if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument('-m',
                       '--mal_pcap',
                       type=str,
                       required=True,
                       help="input malicious traffic (.pcap)")

    parse.add_argument('-b',
                       '--mimic_set',
                       type=str,
                       required=True,
                       help="benign features to mimic (.npy)")

    parse.add_argument('-n',
                       '--normalizer',
                       type=str,
                       required=True,
                       help="compiled feature normalizer (.pkl)")

    parse.add_argument('-i',
                       '--init_pcap',
                       type=str,
                       default=INIT_PCAP,
                       help="preparatory traffic (ignore this if you don't need)")

    parse.add_argument('-o',
                       '--sta_file',
                       type=str,
                       default=STAT_OUTPUT_PATH,
                       help="file saving the final statistics (.pkl)")

    arg = parse.parse_args()

    manip_with_default_params(arg.mal_pcap,
                              arg.mimic_set,
                              arg.normalizer,
                              init_pcap=arg.init_pcap,
                              stat_output=arg.sta_file)
