#!/bin/bash

# **NOTE** katzenpost expects its configuration files to be readable by the
# owner only. Fix the permissions by running this script from within the docker
# directory. (The docker/Makefile runs this automatically.)

chmod -R 700 nonvoting_mixnet/conf/provider?
chmod -R 700 nonvoting_mixnet/conf/mix?
chmod -R 700 nonvoting_mixnet/conf/auth
chmod -R 700 voting_mixnet/conf/auth?
chmod -R 700 voting_mixnet/conf/provider?
chmod -R 700 voting_mixnet/conf/mix?
