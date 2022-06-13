# !/user/bin/env python
"""
Manipulate the traffic at different malicious level
"""

import argparse
from manipulator import Manipulator
from main import INIT_PCAP, W, C1, C2, MAX_ITER, PARTICLE_NUM, LOCAL_GRP_SIZE, GRP_SIZE
import numpy as np
from json import dumps

__author__ = "Zhien Zhang"
__email__ = "zhien.zhang@uqconnect.edu.au"

import os.path

OUTPUT_FOLDER = "./Outputs/Data/IoT_different_levs/ACK_Flooding_Cam_1"
MAL_PATH = "/Volumes/TOSHIBA External USB 3.0 Media/Thesis/Datasets/Datasets/IoT/Raw/Attack Samples/Cam_1/splitted/ACK_Flooding_Cam_1/ACK_Flooding_Cam_1_00000_20210730114134.pcap"
BENIGN_PATH = "/Volumes/TOSHIBA External USB 3.0 Media/Thesis/Datasets/Datasets/IoT/Raw/Benign Samples/" \
              "extracted/05-05-2021_weekday/05-05-2021_weekday_00047_20210505103443.npy"
NORMALIZER_PATH = "models/iot_normalizer.pkl"
PARAMS = {
    0: {
        "min_time_extend": 3,
        "max_time_extend": 6,
        "max_cft_pkt": 3,
        "max_crafted_pkt_prob": 0.05
    },
    4: {
        "min_time_extend": 6,
        "max_time_extend": 13,
        "max_cft_pkt": 1,
        "max_crafted_pkt_prob": 0.05
    },
    5: {
        "min_time_extend": 10,
        "max_time_extend": 17,
        "max_cft_pkt": 1,
        "max_crafted_pkt_prob": 0.05
    },
    6: {
        "min_time_extend": 14,
        "max_time_extend": 20,
        "max_cft_pkt": 1,
        "max_crafted_pkt_prob": 0.05
    }
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("level", type=int, help="the level")
    args = parser.parse_args()
    return args


def main(level: int):
    params = PARAMS[level]
    output_folder = os.path.join(OUTPUT_FOLDER, f"level_{level}")
    os.makedirs(output_folder, exist_ok=True)
    output_stat_path = os.path.join(output_folder, "manipulated.pkl")
    log_path = os.path.join(output_folder, "log.txt")
    os.makedirs(output_folder, exist_ok=True)

    m = Manipulator(MAL_PATH, BENIGN_PATH, NORMALIZER_PATH, INIT_PCAP)
    m.change_particle_params(w=W, c1=C1, c2=C2)
    m.change_pso_params(max_iter=MAX_ITER,
                        particle_num=PARTICLE_NUM,
                        grp_size=LOCAL_GRP_SIZE)
    m.change_manipulator_params(grp_size=GRP_SIZE,
                                min_time_extend=params["min_time_extend"],
                                max_time_extend=params["max_time_extend"],
                                max_cft_pkt=params["max_cft_pkt"],
                                max_crafted_pkt_prob=params["max_crafted_pkt_prob"])

    m.process(output_stat_path, limit=np.Inf, heuristic=False)

    print("Writing log")
    with open(log_path, "a") as fp:
        fp.write(f"original malicious pcap: {MAL_PATH}\n")
        fp.write(f"mimic path: {BENIGN_PATH}\n")
        fp.write(f"manipulator parameters:\n")
        fp.write(dumps(params, indent=2))


if __name__ == "__main__":
    args = parse_args()
    main(args.level)
