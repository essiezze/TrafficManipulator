# !/user/bin/env python
"""
A script for evaluating the anomaly score of the same traffic before and after manipulation.
"""

import sys
sys.path.append("KitNET")
from KitNET.model import exec_model, plot_rmse
from eval import Analyzer
from main import manip_with_default_params
import os
import pickle as pkl

MAX_AE = 10

if __name__=="__main__":
    after_manip_folder = "Outputs/Data/IoT_different_levs/ACK_Flooding_Cam_1/level_6"
    plot_output_folder = "Outputs/Figures/IoT_different_levs/level_6"
    before_manip_rmse_path = "Outputs/Data/IoT_extracted_first/ACK_Flooding_Cam_1/before_manip/original_rmse.pkl"
    mal_path = "/Volumes/TOSHIBA External USB 3.0 Media/Thesis/Datasets/Datasets/IoT/Raw/Attack Samples/Cam_1/splitted/" \
               "ACK_Flooding_Cam_1/ACK_Flooding_Cam_1_00000_20210730114134.pcap"
    after_manip_path = "Outputs/Data/IoT_different_levs/ACK_Flooding_Cam_1/level_6/manipulated.pkl"
    model_path = "models/iot.pkl"

    os.makedirs(plot_output_folder, exist_ok=True)

    with open(model_path, 'rb') as f:
        _ = pkl.load(f)
        _ = pkl.load(f)
        _ = pkl.load(f)
        AD_threshold = pkl.load(f)
    print("AD_threshold:", AD_threshold)

    # evaluate
    after_manip_encodings_path = os.path.join(after_manip_folder, "encodings.pkl")
    after_manip_rmse_path = os.path.join(after_manip_folder, "rmses.pkl")
    after_manip_rmse_plot_path = os.path.join(plot_output_folder, "after_manip.png")
    a = Analyzer(
        org_rmse_file=before_manip_rmse_path,
        org_pcap_file=mal_path,
        sta_data_file=after_manip_path,
        model_save_path=model_path,
        encodings_output_path=after_manip_encodings_path,
        rmse_output_path=after_manip_rmse_path
        # limit = 10000
    )

    a.plt_rmse(AD_threshold,
               title=f"RMSE change before and after manipulation",
               save_path=after_manip_rmse_plot_path)
