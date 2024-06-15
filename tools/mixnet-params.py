#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

import math
import sys
import click

@click.group()
def cli():
    pass

@cli.command()
@click.option("--benchmark", default=0)
@click.option("--gateways", default=0)
@click.option("--nodes-per-layer", default=0)
@click.option("--services", default=0)
@click.option("--users", default=0)
@click.option(
    "--user-loops", default=0, type=float, help="rate of decoy loops per second sent by users"
)
@click.option(
    "--user-traffic", default=0, type=float, help="rate of real messages per second sent by user"
)
@click.option(
    "--node-loops", default=0, type=float, help="rate of decoy loops per second sent by nodes"
)
@click.option("--hops", default=0)
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
    help="LambdaM (overrides --node-loops)",
)
def traffic_per_node(
    benchmark,
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

    if users == 0:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.fail("users must be set.")

    if services == 0:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.fail("services must be set.")

    if nodes_per_layer == 0:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.fail("nodes_per_layer must be set.")

    if gateways == 0:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.fail("gateways must be set.")

    if LambdaP is None:
        if user_traffic == 0:
            ctx = click.get_current_context()
            click.echo(ctx.get_help())
            ctx.fail("Either LambdaP or user_traffic must be set.")
        LambdaP = 10 ** -3 * user_traffic
    else:
        user_traffic = LambdaP / 10**-3

    if LambdaL is None:
        if user_loops == 0:
            ctx = click.get_current_context()
            click.echo(ctx.get_help())
            ctx.fail("Either LambdaL or user_loops must be set.")
        LambdaL = 10 ** -3 * user_loops
    else:
        user_loops = LambdaL / 10**-3

    if LambdaM is None:
        if node_loops == 0:
            ctx = click.get_current_context()
            click.echo(ctx.get_help())
            ctx.fail("Either LambdaM or node_loops must be set.")
        LambdaM = 10 ** -3 * node_loops
    else:
        node_loops = LambdaM / 10**-3

    # total number of nodes producing node loops
    nodes = gateways + services + (nodes_per_layer * (hops-2))

    t = compute_traffic_per_node(
        users,
        user_loops,
        user_traffic,
        nodes,
        node_loops,
        gateways,
        nodes_per_layer,
        services,
    )
    print(
        f"The traffic per node at these settings averages {t} messages per second in the layer with fewest nodes."
    )
    if benchmark > 0:
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

def compute_traffic_per_node(
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

def main():
   cli(prog_name="cli")

if __name__ == '__main__':
   main()
