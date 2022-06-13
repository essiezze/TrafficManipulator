import numpy as np
import matplotlib.pyplot as plt
import pickle as pkl
import executeKitNET.KitNET as eKN
import trainKitNET.KitNET as tKN
import argparse


def RunKN(K,Feature):
    """
    Execute the KitNet and generate results for each set of extracted features.

    :param K: a eKitsune, the KitNet
    :param Feature: features extracted from raw network traffic
    :return: the rmse for each packet
    """
    RMSEs = []
    encodings = []
    output_encodings = (type(K) == eKitsune and K.output_encode)
    for i,x in enumerate(Feature):
        if output_encodings:
            rmse, encoding = K.proc_next_packet(x)
        else:
            rmse = K.proc_next_packet(x)
        if i%1000==0:
            print("--- RunKitNET: Pkts",i,"---")
        if rmse == -1:
            break
        RMSEs.append(rmse)
        if output_encodings:
            encodings.append(encoding)

    if output_encodings:
        return RMSEs, np.array(encodings)
    else:
        return RMSEs


def test_mut(mut_feat,model_save_path, output_encodings=False):

    Feature_Size = mut_feat.shape[1]
    ekn = eKitsune(model_save_path, Feature_Size, 10, output_encode=output_encodings)

    if output_encodings:
        rmse, encodings = RunKN(ekn, mut_feat)
        return rmse, encodings
    else:
        rmse = RunKN(ekn, mut_feat)
        return rmse

"""
The KitNet
"""
class eKitsune:
    
    def __init__(self,model_save_path,feature_size,max_autoencoder_size=10,learning_rate=0.1,hidden_ratio=0.75,output_encode=False):
        
        self.AnomDetector = eKN.KitNET(model_save_path,feature_size,max_autoencoder_size,learning_rate,hidden_ratio)
        self.output_encode = output_encode

    def proc_next_packet(self,x):
        
        return self.AnomDetector.process(x, output_encode=self.output_encode)  # will train during the grace periods, then execute on all the rest.


class tKitsune:
    def __init__(self,model_save_path,n,max_autoencoder_size=10,FM_grace_period=None,AD_grace_period=10000,learning_rate=0.1,hidden_ratio=0.75,):

        self.AnomDetector = tKN.KitNET(model_save_path,n,max_autoencoder_size,FM_grace_period,AD_grace_period,learning_rate,hidden_ratio)

    def proc_next_packet(self,x):

        return self.AnomDetector.process(x)  # will train during the grace periods, then execute on all the rest.


def exec_model(feat_file_path: str, model_path: str, rmse_output_path: str, max_AE, encoding_output_path=None):
    feature = np.load(feat_file_path)
    # feature = feature[arg.FMgrace:]
    feature_size = feature.shape[1]
    # delete pcc-related features
    feature[:, 33:50:4] = 0.
    feature[:, 83:100:4] = 0.
    output_encodings = bool(encoding_output_path)
    ekn = eKitsune(model_path, feature_size, max_AE, output_encode=output_encodings)

    encodings = None
    if output_encodings:
        rmse, encodings = RunKN(ekn, feature)
    else:
        rmse = RunKN(ekn, feature)
    rmse = np.array(rmse)
    with open(rmse_output_path, 'wb') as f:
        pkl.dump(rmse, f)
    with open(model_path, "rb") as f:
        _ = pkl.load(f)
        _ = pkl.load(f)
        _ = pkl.load(f)
        AD_threshold = pkl.load(f)

    # save encoding
    if output_encodings:
        with open(encoding_output_path, 'wb') as f:
            pkl.dump(encodings, f)

    return AD_threshold, rmse


def plot_rmse(AD_threshold, rmse, title="RMSE of Test set", save_path=None):
    x = np.arange(0, len(rmse), 1)
    plt.figure()
    plt.scatter(x, rmse, s=12, c='r')
    plt.plot(x, [AD_threshold] * len(rmse), c='black', linewidth=2, label="AD_threshold")
    plt.title(title)
    plt.xlabel('pkt no.')
    plt.ylabel('RMSE in Kitsune')
    plt.legend()
    if not save_path:
        plt.show()
    else:
        plt.savefig(save_path, dpi=300)


if __name__ == "__main__":
    parse = argparse.ArgumentParser()

    parse.add_argument('-M', '--mode', type=str, default='exec', help="{train,exec}")

    path_to_feat_file_arg_group = parse.add_mutually_exclusive_group(required=True)
    path_to_feat_file_arg_group.add_argument('-tf', '--feat_file_path', type=str,
                                             help="train or execute feature file path (.npy)")
    path_to_feat_file_arg_group.add_argument('-tfs', '--path_to_feat_files', type=str,
                                             help="path to a file storing multiple feature file paths for training")

    parse.add_argument('-rf', '--RMSE_file_path', type=str,
                       help="resulting rmse file (.pkl) path, only for execute mode!")

    parse.add_argument('-mf', '--model_file_path', type=str, default='./example/model.pkl',
                       help="for train mode, model is saved into 'mf'; for execute mode, model is loaded from 'mf'")

    parse.add_argument('-m', '--maxAE', type=int, default=10,
                       help="maximum size for any autoencoder in the ensemble layer")
    parse.add_argument('-fm', '--FMgrace', type=int, default=5000,
                       help="the number of instances taken to learn the feature mapping (the ensemble's architecture)")
    parse.add_argument('-ad', '--ADgrace', type=int, default=50000,
                       help="the number of instances used to train the anomaly detector (ensemble itself)")
    parse.add_argument('-e', '--encoding_path', dest='encoding_path', type=str, default=None,
                        help='Output path for the encodings, only for execution mode')

    arg = parse.parse_args()

    if arg.mode == 'train':
        print("Warning: under TRAIN mode!")
        feature_size = None
        feat_files = []
        tkn = None

        if arg.feat_file_path:
            feat_files.append(arg.feat_file_path)
        else:
            newline = None
            with open(arg.path_to_feat_files) as fp:
                newline = fp.readline().rstrip()
                while newline != "":
                    if not newline.isspace():
                        feat_files.append(newline)
                    newline = fp.readline().rstrip()

        # train
        rmses = []
        for feat_file_path in feat_files:
            print(f"Start training with {feat_file_path}")
            feature = np.load(feat_file_path)
            feature = feature[:arg.FMgrace + arg.ADgrace]
            if feature_size is None:
                feature_size = feature.shape[1]
            elif feature_size != feature.shape[1]:
                raise RuntimeError("Feature size does not match!")

            if tkn is None:
                tkn = tKitsune(arg.model_file_path, feature_size, arg.maxAE, arg.FMgrace, arg.ADgrace)

            rmses.extend(RunKN(tkn, feature))

        AD_threshold = max(rmses[arg.FMgrace:])

        # x = np.arange(0,len(rmse),1)
        # plt.scatter(x,rmse)
        # plt.show()

        print(f"Number of feature files: {len(feat_files)}")
        print(f"Number of packets trained: {tkn.AnomDetector.n_trained}")
        print("AD_threshold:", AD_threshold)

        with open(arg.model_file_path, "ab") as f:
            pkl.dump(AD_threshold, f)

    elif arg.mode == 'exec':
        print("Warning: under EXECUTE mode!")

        AD_threshold, rmse = exec_model(arg.feat_file_path,
                                        arg.model_file_path,
                                        arg.RMSE_file_path,
                                        arg.maxAE,
                                        encoding_output_path=arg.encoding_path)

        print('AD_threshold:', AD_threshold)
        print('# rmse over AD_t:', rmse[rmse > AD_threshold].shape)
        print('Total number:', len(rmse))
        print("rmse mean:", np.mean(rmse))

        plot_rmse(AD_threshold, rmse)
    else:
        raise RuntimeError("argument -M is wrong! choose 'train' or 'execute'")
    

