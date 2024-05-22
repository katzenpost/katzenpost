#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only


import math
import sys



def main():
    benchmark=sys.argv[0]

    average_delay = 0.2 #average delay is 0.2s
    gateways = 2
    nodes_per_layer = 2
    services = 2

    #user traffic generation
    user_loops = 0.5 #users send 0.5 loops per second
    user_traffic = 1 #users send 1 decoys or messages per second
    node_loops = 0.5 #nodes send 0.5 loops per second
    hops = 11

    #verify that the parameters are right
    mu = 10**(-3)/average_delay
    IP = 10**(-3)*user_traffic
    IL = 10**(-3)*user_loops
    IM = 10**(-3)*node_loops
    
    l=1/average_delay

    #total number  of nodes producing node loops
    nodes = gateways+services+nodes_per_layer*3
    
    print("The traffic per node at these settings averages ",traffic_per_node(1000)," per second in the layer with fewest nodes.") #ops per per second node with 700 users
    print("The maximum number of Sphinx operations is ",max_ops(benchmark)) #benchmark right now is t.2 small kem ns/op
    print()
    print("mu is",mu)
    print("IP is",IP)
    print("IL is",IL)
    print("IM is",IM)


def max_ops(benchmark):
    b=10**(-9)*benchmark #ns to s
    return 1/b




# total user traffic entering the network per second times 2, 
# the 2 is because every client packet crosses each layer twice
# node loops only need to pass a layer once
def traffic_per_layer(users,user_traffic):
    per_user=user_traffic+user_loops
    total_user_traffic = 2*users*per_user
    total_traffic = total_user_traffic + nodes*node_loops
    return total_traffic

def traffic_per_node(x):
    a=min(gateways,nodes_per_layer,services)
    b=traffic_per_layer(x)/a
    return b

if __name__ == "__main__":
    main()

