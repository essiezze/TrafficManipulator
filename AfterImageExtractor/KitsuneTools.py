import os.path

import numpy as np

STOP_FLAG = 999999999.

# Input: K
def RunFE(
            K,                      # the FE object usd to extract features
            origin_pos=None,        # what does it mean?
            output_file=".csv",     # output filename, the default value means does not write the features to file
            show_info=True,
            split_size=None         # output features into files with no more than split_size number of pkts
          ):
    # NOTE: split_size not implemented if original_pos != None
    if show_info:
        print("@RunFE: Running Feature Extractor...")
    features = []
    all_features = []
    output_folder = os.path.dirname(output_file)
    output_fname = os.path.basename(output_file)
    output_fname_base, suffix = output_fname.split(".")

    file_counter = 0
    if origin_pos is None:
        i = 0
        while True:
            tmpx = K.proc_next_packet()

            # if reached the end of the file, write the features to file
            if tmpx[0] == STOP_FLAG:
                output_path = f"{os.path.join(output_folder, output_fname_base)}_{file_counter}.{suffix}"
                _write_features(output_path, features)
                if show_info:
                    print(f"{output_path} created")
                    print("All features extracted")
                break

            features.append(tmpx)
            i += 1
            
            # write to file every split_size features
            if split_size != None and (i % split_size) == 0:
                output_path = f"{os.path.join(output_folder, output_fname_base)}_{file_counter}.{suffix}"
                _write_features(output_path, features)
                if show_info:
                    print(f"{output_path} created")
                file_counter += 1
                features = []

    else:
        i = 0
        j = 0
        while True:
            tmpx = K.proc_next_packet()
            if tmpx[0] == STOP_FLAG:
                if show_info:
                    print("@RunFE: Finish Feature Extractor...")
                break
            all_features.append(tmpx)
            if j < len(origin_pos) and i == origin_pos[j]:
                features.append(tmpx)
                j += 1
            i += 1

    if origin_pos and output_file != ".csv":
        _write_features(output_file, features)
        if show_info:
            print("@RunFE: Features are saved in .csv file!")

    return features,all_features


def _write_features(output_file: str, features):
    np.save(output_file, np.array(features))


def safelyCopyNstat(ns,roll_back_flag):   # 2020.04
    ns.HT_jit.roll_back = roll_back_flag
    ns.HT_MI.roll_back = roll_back_flag
    ns.HT_H.roll_back = roll_back_flag
    ns.HT_Hp.roll_back = roll_back_flag
    return ns

# def RunKN(
#             K,
#             Feature,
#           ):
#     RMSEs = []
#     for x in Feature:
#         rmse = K.proc_next_packet(x)
#         if rmse == -1:
#             break
#         RMSEs.append(rmse)
#     return RMSEs
