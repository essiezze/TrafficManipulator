# !/user/bin/env python
"""
Util functions for converting manipulated traffic into pcap files
"""

from rebuilder import rebuild
import pickle as pkl
from math import modf
from scapy.all import *

__author__ = "Zhien Zhang"
__email__ = "zhien.zhang@uqconnect.edu.au"


def from_stat_file_to_pcap(stat_path: str, output_path: str):
	"""
	Write manipulated traffic to pcap file

	:param stat_path: the path to the output statistic file of the manipulator
	:param output_path: the output path of the pcap file
	"""
	X, pkts_in_groups = get_pkts_from_stat_file(stat_path)

	# reconstruct
	pkts = list()
	# reconstruct packets in each group
	for i in range(len(X)):
		group_size = len(X[0].mal)
		pkts.extend(rebuild(group_size, X[0], pkts_in_groups[0]))

	writer = PcapWriter(output_path)
	for pkt in pkts:
		# write header
		if not writer.header_present:
			writer.write_header(pkt)

		# preserve the time stamp of the pkt
		msec, sec = modf(pkt.time)
		sec = int(sec)
		msec = int(1000 * msec)

		writer.write_packet(pkt, sec=sec, usec=msec)

	writer.close()


def get_pkts_from_stat_file(stat_path: str):
	"""
	Load the manipulated packets from the output statistic file of the manipulator
	: param stat_path: path to the statistic file
	"""
	with open(stat_path, "rb") as fp:
		X = pkl.load(fp)
		_ = pkl.load(fp)
		pkts_in_groups = pkl.load(fp)

	return X, pkts_in_groups
