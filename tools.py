import pickle as pkl
import numpy as np
import argparse
from utils import *

"""
Generates the normalizer for the Kitsune
"""

if __name__ == "__main__":

    parse = argparse.ArgumentParser()

    parse.add_argument('-M', '--mode', type=str, default='CK', help="{CK:compiling KNnormalizer,}")

    path_to_feat_file_arg_group = parse.add_mutually_exclusive_group(required=True)
    path_to_feat_file_arg_group.add_argument('-tf', '--feat_file_path', type=str,
                                             help="train feature file path (.npy)")
    path_to_feat_file_arg_group.add_argument('-tfs', '--path_to_feat_files', type=str,
                                             help="path to a file storing multiple feature file paths for training")

    parse.add_argument('-mf', '--model_file_path', type=str, default='./example/model.pkl',
                       help="model saved file path (.pkl)")

    parse.add_argument('-nf', '--normalizer_file_path', type=str, default='./example/normalizer.pkl',
                       help="normalizer file path to save (.pkl)")

    parse.add_argument('-fm', '--FMgrace', type=int, default=5000,
                       help="the number of instances taken to learn the feature mapping (the ensemble's architecture)")
    parse.add_argument('-ad', '--ADgrace', type=int, default=50000,
                       help="the number of instances used to train the anomaly detector (ensemble itself)")

    arg = parse.parse_args()

    if arg.feat_file_path:
        train_feat = np.load(arg.feat_file_path)
    else:
        train_feats = []
        line = None
        with open(arg.path_to_feat_files) as fp:
            line = fp.readline().rstrip()
            while line != "":
                if not line.isspace():
                    train_feats.append(np.load(line))
                    print(f"{line} loaded")

                line = fp.readline().rstrip()
        train_feat = np.concatenate(train_feats, axis=0)

    knormer = KNnormalizer(arg.model_file_path)
    knormer.fit_transform(train_feat[arg.FMgrace:arg.ADgrace])

    with open(arg.normalizer_file_path,'wb') as f:
        pkl.dump(knormer,f)
