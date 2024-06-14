#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only


import math
import sys
import click


@click.command()
@click.option("--benchmark", default=385069)
@click.option("--average-delay", default=0.2, help="per second")
@click.option("--gateways", default=2)
@click.option("--nodes-per-layer", default=2)
@click.option("--services", default=2)
@click.option("--users", default=2000)
@click.option(
    "--user-loops", default=0.5, help="rate of decoy loops per second sent by users"
)
@click.option(
    "--user-traffic", default=1, help="rate of real messages per second sent by user"
)
@click.option(
    "--node-loops", default=0.5, help="rate of decoy loops per second sent by nodes"
)
@click.option("--hops", default=11)
@click.option(
    "-P",
    "--LambdaP",
    "LambdaP",
    type=float,
    default=None,
    help="LambdaP (overrides --user-traffic)",
)
@click.option(
    "-L",
    "--LambdaL",
    "LambdaL",
    type=float,
    default=None,
    help="LambdaL (overrides --user-loops)",
)
@click.option(
    "-M",
    "--LambdaM",
    "LambdaM",
    type=float,
    default=None,
    help="LambdaP (overrides --node-loops)",
)
def main(
    benchmark,
    average_delay,
    gateways,
    nodes_per_layer,
    services,
    users,
    user_loops,
    user_traffic,
    node_loops,
    hops,
    LambdaP,
    LambdaL,
    LambdaM,
):

    if LambdaP is None:
        LambdaP = 10 ** (-3) * user_traffic
    else:
        user_traffic = LambdaP / 10**-3

    if LambdaL is None:
        LambdaL = 10 ** (-3) * user_loops
    else:
        user_loops = LambdaL / 10**-3

    if LambdaM is None:
        LambdaM = 10 ** (-3) * node_loops
    else:
        node_loops = LambdaM / 10**-3

    l = 1 / average_delay

    # total number of nodes producing node loops
    nodes = gateways + services + nodes_per_layer * 3

    t = traffic_per_node(
        users,
        user_loops,
        user_traffic,
        nodes,
        node_loops,
        gateways,
        nodes_per_layer,
        services,
    )

    #    for (
    #        key
    #    ) in "average_delay user_traffic LambdaP user_loops LambdaL node_loops LambdaM gateways nodes_per_layer services hops users".split():
    print(
        sys.argv[0]
        + " \\\n"
        + "\n".join(
            f"{'--'+key.replace('_','-'):>15} {value} \\"
            for key, value in {
                key: locals()[key]
                for key in dict(
                    click.get_current_context().params,
                    **{f"Lambda{x}": None for x in "PLM"},
                )
            }.items()
        )
    )

    print(
        f"The traffic per node at these settings averages {t} messages per second in the layer with fewest nodes."
    )
    print("The maximum number of Sphinx operations is ", max_ops(benchmark))
    print(f"parameters for genconfig: -lP {LambdaP} -lL {LambdaL} -lM {LambdaM}")

    if t > max_ops(benchmark):
        print("WARNING: Sphinx unwrap per second mix node capacity is too low.")


def max_ops(benchmark):
    # nanosecond to second
    b = 10 ** (-9) * benchmark
    return 1 / b


# total user traffic entering the network per second times 2,
# the 2 is because every client packet crosses each layer twice
# node loops only need to pass a layer once
def traffic_per_layer(users, user_loops, user_traffic, nodes, node_loops):
    per_user = user_traffic + user_loops
    total_user_traffic = 2 * (users * per_user)
    total_traffic = total_user_traffic + (nodes * node_loops)
    return total_traffic


def traffic_per_node(
    users,
    user_loops,
    user_traffic,
    nodes,
    node_loops,
    gateways,
    nodes_per_layer,
    services,
):
    a = min(gateways, nodes_per_layer, services)
    b = traffic_per_layer(users, user_loops, user_traffic, nodes, node_loops) / a
    return b


if __name__ == "__main__":
    main()
