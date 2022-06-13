from particle import Particle
import numpy as np
from scapy.all import *


class PSO:
    """
    PSO-based Automatic traffic mutation on a series of pkts
    """
    def __init__(self, max_iter, particle_num, grp_size=0, alg='L'):
        self.max_iter = max_iter            # num of the eval and update rounds
        self.particle_num = particle_num    # num of total candidate mutants
        self.grp_size = grp_size            # num of candidate mutants

        self.grp_best_dis = [-1.] * (self.particle_num // self.grp_size)
        self.grp_best_index = [-1] * (self.particle_num // self.grp_size)

        self.global_best_dis = -1.
        self.global_best_index = -1

        self.global_best_pktlist = None

        self.swarm = []     # candidates

        self.STA_glb_dis_list = []
        self.STA_avg_dis_list = []

    def execute(
        self,
        last_end_time,          # the timestamp of the pkt right before the first pkl in groupList
        groupList,              # the malicious pkts for manipulation
        max_time_extend,
        max_cft_pkt,
        min_time_extend,
        max_crafted_pkt_prob,
        mimic_set,  # evaluate
        nstat,  # evaluate
        # tmp_pcap_file,
        knormer,
        w,
        c1,
        c2,
        show_info=True,
        heuristic=False,
    ):

        # print("*" * 64)
        # establish the swarm
        # print("--@PSO: Creating particle swarm...")
        for i in range(self.particle_num):
            # print("PSO:",max_cft_pkt)
            self.swarm.append(
                Particle(last_end_time, groupList, max_time_extend,
                         max_cft_pkt, min_time_extend, max_crafted_pkt_prob))

        # begin optimization loop
        # print("--@PSO: Executing PSO algorithm...")

        FE_time = 0
        last_glb_best = np.Inf
        iter = 0
        while True:
            avg_dis = 0
            # iterate through each group of particles
            for i in range(0, self.particle_num, self.grp_size):

                # print("--@PSO: process grp %d, no.%d~%d"%(i/self.grp_size,i,i+self.grp_size-1), "...")
                # iterate through each particle in the group and find the one with the best score
                for j in range(i, i + self.grp_size):
                    # evaluate the particle
                    grp_i = int(i / self.grp_size)
                    FE_time += self.swarm[j].evaluate(mimic_set, nstat,
                                                      knormer)  # tmp_pcap_file
                    avg_dis += self.swarm[j].dis

                    # check if the particle is the best in the group
                    if self.swarm[j].dis < self.grp_best_dis[
                            grp_i] or self.grp_best_dis[grp_i] == -1.:
                        self.grp_best_index[grp_i] = j
                        self.grp_best_dis[grp_i] = self.swarm[j].dis

                # check if the group best is the best among all groups
                if self.grp_best_dis[
                        grp_i] < self.global_best_dis or self.global_best_dis == -1.:
                    self.global_best_index = self.grp_best_index[grp_i]
                    self.global_best_dis = self.grp_best_dis[grp_i]

                grp_best_X = self.swarm[self.grp_best_index[grp_i]].X

                # update the particles in the group w.r.t. the group best
                for j in range(i, i + self.grp_size):
                    # print("--@PSO: update_V swarm", j, "...")
                    self.swarm[j].update_v(grp_best_X, w, c1, c2)
                    # print("--@PSO: update_X swarm", j, "...")
                    self.swarm[j].update_x()

            self.STA_glb_dis_list.append(self.global_best_dis)
            self.STA_avg_dis_list.append(avg_dis / self.particle_num)

            if show_info:
                print("--@PSO:Step", iter, "Finished...Global best value:",
                      self.global_best_dis)

            # enhanced mode
            if heuristic:
                if last_glb_best > self.global_best_dis * (
                        1. + 0.1):  # delta must > 10%
                    last_glb_best = self.global_best_dis
                    iter -= 1
            iter += 1
            if iter >= self.max_iter:
                break

        self.global_best_pktlist = self.swarm[self.global_best_index].pktList

        STA_best_X = self.swarm[self.global_best_index].X
        STA_best_feature = self.swarm[self.global_best_index].feature
        STA_best_pktList = self.global_best_pktlist

        STA_best_all_feature = self.swarm[self.global_best_index].all_feature

        cur_end_time = self.swarm[self.global_best_index].X.mal[-1][0]
        ics_time = cur_end_time - float(groupList[-1].time)

        return ics_time, cur_end_time, STA_best_X, STA_best_feature, STA_best_pktList, self.STA_glb_dis_list, self.STA_avg_dis_list, STA_best_all_feature, FE_time
