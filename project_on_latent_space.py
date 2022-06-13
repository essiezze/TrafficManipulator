# !/user/bin/env python
"""
Projects the anomaly score of different attack onto the reduced latent space of Kitsune
"""

import os  # import statements
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

__author__ = "Zhien Zhang"
__email__ = "zhien.zhang@uqconnect.edu.au"

ATTACKS = ["ARP_Spoofing_Cam_1",
           "Port_Scanning_Cam_1",
           "Service_Detection_Cam_1",
           "SYN_Flooding_Cam_1",
           "UDP_Flooding_Cam_1"]

ATTACKS_NAME = {
    "ARP_Spoofing_Cam_1": "ARP Spoofing",
    "Port_Scanning_Cam_1": "Port Scanning",
    "Service_Detection_Cam_1": "Service Detection",
    "SYN_Flooding_Cam_1": "SYN Flooding",
    "UDP_Flooding_Cam_1": "UDP Flooding"
}
GLOBAL_MIN = 0.012349050418203118
GLOBAL_MAX = 2.3497434047035317

input_folder_upper = "Outputs/Data/IoT_extracted_first"
output_folder_upper = "Outputs/Figures/IoT_extracted_first"
before_folder = "before_manip"
after_folder = "after_manip"
rmse_fname = "rmses.pkl"
encodings_fname = "encodings.pkl"


def plot_on_latent_space(attack: str):
    before_encodings_path = os.path.join(input_folder_upper, attack, before_folder, encodings_fname)
    after_encodings_path = os.path.join(input_folder_upper, attack, after_folder, encodings_fname)
    before_encodings = np.array(np.load(before_encodings_path, allow_pickle=True))
    after_encodings = np.array(np.load(after_encodings_path, allow_pickle=True))

    # pca
    sc = StandardScaler()
    latent_std = sc.fit_transform(before_encodings)
    cov_mat = np.cov(latent_std.T)
    eigen_vals, eigen_vecs = np.linalg.eig(cov_mat)
    W = eigen_vecs[:, 0:2]
    before_latent_pca = before_encodings.dot(W)
    after_latent_pca = after_encodings.dot(W)

    # get rmse
    before_rmse_path = os.path.join(input_folder_upper, attack, before_folder, rmse_fname)
    after_rmse_path = os.path.join(input_folder_upper, attack, after_folder, rmse_fname)
    before_rmse = np.load(before_rmse_path, allow_pickle=True)
    after_rmse = np.load(after_rmse_path, allow_pickle=True)

    # sample traffic for plotting
    if len(before_rmse) > 1000:
        rand_idx = np.random.choice(len(before_rmse), 1000, replace=False)
    else:
        rand_idx = np.arange(0, len(before_rmse), 1)

    # plot
    sns.set_theme()
    fig, (ax1, ax2) = plt.subplots(1, 2, sharey=True, figsize=(15, 5))
    fig.suptitle(f"The RMSE Scores of {ATTACKS_NAME[attack]} Projected on the Latent Space", fontsize=18)
    global_min = GLOBAL_MIN
    global_max = GLOBAL_MAX

    # before manip
    sns.scatterplot(x=before_latent_pca[rand_idx, 0], y=before_latent_pca[rand_idx, 1], hue=before_rmse[rand_idx],
                    ax=ax1, s=100, hue_norm=(global_min, global_max))
    ax1.set_xlim([-0.75, 1.25])
    ax1.set_ylim([-0.45, 1])
    handles, labels = ax1.get_legend_handles_labels()
    ax1.get_legend().remove()
    ax1.set_title("Before Manipulation", fontsize=16)

    # after manip
    sns.scatterplot(x=after_latent_pca[rand_idx, 0], y=after_latent_pca[rand_idx, 1], hue=after_rmse[rand_idx],
                    ax=ax2, s=100, hue_norm=(global_min, global_max))
    fig.legend(handles, labels, loc='upper right')
    ax2.set_xlim([-0.75, 1.25])
    ax2.get_legend().remove()
    ax2.set_title("After Manipulation", fontsize=16)

    fig.supxlabel('PC1')
    fig.supylabel('PC2')
    fig_output_path = os.path.join(output_folder_upper, attack, "comparison_rmse_latent.png")
    fig.savefig(fig_output_path, dpi=500)


if __name__ == "__main__":
    for attack in ATTACKS:
        print(f"Processing {attack}")
        plot_on_latent_space(attack)

