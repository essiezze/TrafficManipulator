# Experiments on Kitsune and the traffic manipulator

This forked branch of the traffic manipulator, 
proposed by Han, et al[1] is for the code that carried out a 
series of experiments on the traffic manipulator and Kitsune[2].

A few changes have been made to the code of Kitsune and the 
feature extractors to support a streamed processing when 
handling large inputs:
 - Instead of storing all the extracted features in the buffer before writing,
the feature extractor in this repo takes an extra parameter indicating the maximum
number of allowed features to be stored in memory before writing out. Once the 
maximum has been reached, the feature extractor will write out all the features in memory
into a numbered`.npy` file.
   - Usage can be found in `extract_multi.py`
 - Instead of reading all the packets from an input `.pcap` file into the memory to detect th anomaly level
of the traffic, Kitsune is able to read and process only one packet at a time to reduce the memory
consumption when processing large traffic data.

In order to explore the relationship between the output anomaly
level and the latent space of the output autoencoder in Kitsune,
extra parameters has been added to be able to save the latent
code of the traffic tested with Kitsune.

## Scripts
This branch also added a few scripts at the root directory
to make the manipulation, extraction and evaluation process more scalable,
or can be launched from a script easily:
- `evaluate.py`: the script that can evaluate the anomaly level
of the traffic before and after manipulation with the resulting 
plot saved.
- `extract_multi.py`: a script to extract features into smaller
sub-files.
- `io_utiles.py`: functions for converting manipulated traffics
stored in a `.pkl` file to a `.pcap` file with the manipulated 
timestamp preserved.
- `manip_all.py`: a script that does the manipulation and evaluation
together.
- `manip_levels.py`: a script for manipulating the same input 
traffic with different parameters at once.
- `project_on_latent_space.py`: a script for projecting the 
anomaly score of the traffic before and after manipulation onto
the latent space.

## References
[1] D. Han, Z. Wang, Y. Zhong, et al., “Evaluating and improving adversarial robustness of machine learning-based network intrusion detectors,” eng, IEEE journal on selected areas in communications, vol. 39, no. 8, pp. 2632–2647, 2021, issn: 0733-8716.

Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, “Kitsune: An ensemble of autoencoders for online network intrusion detection,” eng, 2018.[2] 
