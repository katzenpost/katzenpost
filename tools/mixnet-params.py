#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

import math
import sys
import click

@click.group()
@click.option('--verbose', default=False)
def cli(verbose):
    if verbose:
        click.echo("verbose mode is on")

@cli.command()
@click.argument('users')
@click.argument('mu')
@click.argument('lambda_m')
@click.argument('lambda_p')
@click.argument('lambda_d')
@click.argument('lambda_l')
@click.argument('gateway_nodes')
@click.argument('service_nodes')
@click.argument('mixes_per_layer')
@click.option('--sphinx_benchmark', default=0, help='nanosecond benchmark timing of one Sphinx unwrap operation.')
def traffic_per_node(users, mu, lambda_m, lambda_p, lambda_d, lambda_l, gateway_nodes, service_nodes, mixes_per_layer, sphinx_benchmark):

    # XXX FIXME: Do something with lambda_d.
    # XXX Do something with mu?

    user_traffic = 1/float(lambda_p)
    user_loops = 1/float(lambda_l)
    
    # total number of nodes producing node loops
    nodes = gateway_nodes + service_nodes + (mixes_per_layer * 3)

    node_loops = 1/float(lambda_m)
    
    t = calc_traffic_per_node(users, user_loops, user_traffic, nodes, node_loops, gateway_nodes, mixes_per_layer, service_nodes)
    click.echo("Per node traffic is {}".format(t))

    if sphinx_benchmark != 0:
        if t > max_ops(sphinx_benchmark):
            click.echo("WARNING: Sphinx unwrap per second mix node capacity is too low.")
        else:
            click.echo("Sphinx performance is within range.")

def max_ops(benchmark):
    # nanosecond to second
    b=10**(-9)*benchmark
    return 1/b

# total user traffic entering the network per second times 2, 
# the 2 is because every client packet crosses each layer twice
# node loops only need to pass a layer once
def traffic_per_layer(users, user_loops, user_traffic, nodes, node_loops):
    per_user=user_traffic + user_loops
    total_user_traffic = 2 * (float(users) * per_user)
    total_traffic = total_user_traffic + (float(nodes) * node_loops)
    return total_traffic

def calc_traffic_per_node(users, user_loops, user_traffic, nodes, node_loops, gateways, nodes_per_layer, services):
    a=float(min(gateways,nodes_per_layer,services))
    b=traffic_per_layer(users, user_loops, user_traffic, nodes, node_loops)/a
    return b

def main():
   cli(prog_name="cli")

if __name__ == '__main__':
   main()
