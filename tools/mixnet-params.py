#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only


import math
import sys
import click


@click.command()
@click.option("--benchmark", default=385069)
@click.option("--average_delay", default=0.2, help="per second")
@click.option("--gateways", default=2)
@click.option("--nodes-per-layer", default=2)
@click.option("--services", default=2)
@click.option("--users", default=2000)
@click.option("--user_loops", default=0.5, help="users send 0.5 loops per second")
@click.option(
    "--user_traffic", default=1, help="users send 1 decoys or messages per second"
)
@click.option("--node_loops", default=0.5, help="nodes send 0.5 loops per second")
@click.option("--hops", default=11)
def main(**kwargs):

    globals().update(**kwargs)

    mu = 10 ** (-3) / average_delay
    IP = 10 ** (-3) * user_traffic
    IL = 10 ** (-3) * user_loops
    IM = 10 ** (-3) * node_loops

    l = 1 / average_delay

    global nodes
    # total number of nodes producing node loops
    nodes = gateways + services + nodes_per_layer * 3

    t = traffic_per_node()

    print(f"Parameters: nodes={nodes} l={l} args={kwargs}")
    print(
        f"The traffic per node at these settings averages {t} messages per second in the layer with fewest nodes."
    )
    print("The maximum number of Sphinx operations is ", max_ops(benchmark))
    print(f"parameters for genconfig: -mu {mu} -lP {IP} -lL {IL} -lM {IM}")

    if t > max_ops(benchmark):
        print("WARNING: Sphinx unwrap per second mix node capacity is too low.")


def max_ops(benchmark):
    # nanosecond to second
    b = 10 ** (-9) * benchmark
    return 1 / b


# total user traffic entering the network per second times 2,
# the 2 is because every client packet crosses each layer twice
# node loops only need to pass a layer once
def traffic_per_layer():
    per_user = user_traffic + user_loops
    total_user_traffic = 2 * (users * per_user)
    total_traffic = total_user_traffic + (nodes * node_loops)
    return total_traffic


def traffic_per_node():
    a = min(gateways, nodes_per_layer, services)
    b = traffic_per_layer() / a
    return b


if __name__ == "__main__":
    main()
