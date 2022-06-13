import sys
sys.path.append("KitNET")
from KitNET.model import exec_model, plot_rmse
from eval import Analyzer
from main import manip_with_default_params
import os
from contextlib import redirect_stdout
from random import choice
import numpy as np
import argparse

MAX_AE = 10


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("attack_type", type=str, help="the type of the attack")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    all_attacks = [args.attack_type]

    output_upper_folder = "Outputs/Data/IoT_extracted_first"
    fig_output_upper_folder = "Outputs/Figures/IoT_extracted_first"
    traffic_folder = "/Volumes/TOSHIBA External USB 3.0 Media/Thesis/Datasets/Datasets/IoT/Raw/Attack Samples/Cam_1"
    original_malicious_folder = "splitted"
    original_feat_folder = "extracted_first"
    model_path = "models/iot.pkl"
    benign_path = "/Volumes/TOSHIBA External USB 3.0 Media/Thesis/Datasets/Datasets/IoT/Raw/Benign Samples/" \
                  "extracted/05-05-2021_weekday/05-05-2021_weekday_00047_20210505103443.npy"
    normalizer_path = "models/iot_normalizer.pkl"

    finished = []

    for attack in all_attacks:
        if attack not in finished and not attack.startswith("."):
            print(f"Start processing {attack}")

            # output paths
            output_folder = os.path.join(output_upper_folder, attack)
            os.makedirs(output_folder, exist_ok=True)
            plot_output_folder = os.path.join(fig_output_upper_folder, attack)
            os.makedirs(plot_output_folder, exist_ok=True)
            log_path = os.path.join(output_folder, "log.txt")

            # select one .pcap file as the attack traffic to manipulate
            attack_files = os.listdir(os.path.join(traffic_folder, original_malicious_folder, attack))
            if len(attack_files) == 1:
                attack_file = attack_files[0]
            else:
                attack_file = choice(attack_files)
            with open(log_path, "w") as fp:
                fp.write("Malicious traffic: \n")
                fp.write(f"{attack_file}\n")

            # get split number
            split_num = int(attack_file.split("_")[-2])

            # test the original malicious traffic
            # output paths
            before_manip_folder = os.path.join(output_folder, "before_manip")
            os.makedirs(before_manip_folder, exist_ok=True)
            before_manip_encodings_path = os.path.join(before_manip_folder, "encodings.pkl")
            before_manip_rmse_path = os.path.join(before_manip_folder, "rmses.pkl")
            before_manip_rmse_plot_path = os.path.join(plot_output_folder, "before_manip.png")
            # input_paths
            mal_feat_path = os.path.join(traffic_folder, original_feat_folder, attack, f"{attack}_{split_num}.npy")
            AD_threshold, rmse = exec_model(mal_feat_path,
                                            model_path,
                                            before_manip_rmse_path,
                                            MAX_AE,
                                            encoding_output_path=before_manip_encodings_path)
            with open(log_path, "a") as fp:
                fp.write("\n")
                fp.write("BEFORE MANIPULATION\n")
                fp.write(f"AD_threshold: {AD_threshold}\n")
                fp.write(f"# rmse over AD_t: {rmse[rmse > AD_threshold].shape[0]}\n")
                fp.write(f'Total number: {len(rmse)}\n')
                fp.write(f"rmse mean: {np.mean(rmse)}\n")

            plot_rmse(AD_threshold, rmse,
                      title=f"RMSE of {attack} before manipulation",
                      save_path=before_manip_rmse_plot_path)

            # manipulate
            after_manip_folder = os.path.join(output_folder, "after_manip")
            os.makedirs(after_manip_folder, exist_ok=True)
            after_manip_path = os.path.join(after_manip_folder, "manipulated.pkl")
            mal_path = os.path.join(traffic_folder, original_malicious_folder, attack, attack_file)
            manip_with_default_params(mal_path, benign_path, normalizer_path, stat_output=after_manip_path)
            with open(log_path, "a") as fp:
                fp.write("\n")
                fp.write("MANIPULATION\n")
                fp.write(f"Benign traffic to mimic: {os.path.basename(benign_path)}\n")

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
            with open(log_path, "a") as fp:
                with redirect_stdout(fp) as output:
                    a.eval(AD_threshold,
                           benign_path,
                           mal_feat_path,
                           normalizer_path,
                           need_mmr=True)
            print(f"Finished evaluating {attack}")
            a.plt_rmse(AD_threshold,
                       title=f"RMSE change before and after manipulation",
                       save_path=after_manip_rmse_plot_path)

            # clear global variables set in the manipulation
            # del globals()["STA_X_LIST"]
            # del globals()["STA_feature_list"]
            # del globals()["STA_pktList_list"]
            # del globals()["STA_gbl_dis_list"]
            # del globals()["STA_avg_dis_list"]

