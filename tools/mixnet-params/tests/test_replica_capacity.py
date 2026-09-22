# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify the replica CTIDH capacity model, using namenlos's real deployment
(couriers=3, replicas=4, LambdaR=0.02 -- see ~/namenlos/configs/SSOT/topology.toml)
as the concrete worked example.
"""

import pytest

from mixnet_params.replica_capacity import (
    concurrent_users_ceiling,
    default_decaps_per_request,
    replica_inbound_connections,
    replica_mesh_pps,
)


def test_default_decaps_per_request_low_regime():
    # numReplicas < 4: intermediates ARE the K=2 shard holders, no proxying.
    assert default_decaps_per_request(2) == (2, 2, 2)
    assert default_decaps_per_request(3) == (2, 2, 2)


def test_default_decaps_per_request_namenlos_regime():
    # namenlos runs 4 replicas: intermediates exclude the shard holders, so
    # every request is proxied to them too.
    assert default_decaps_per_request(4) == (4, 4, 6)
    assert default_decaps_per_request(10) == (4, 4, 6)


def test_concurrent_users_ceiling_worked_example():
    # 112 ops/sec system-wide, 0.01 req/sec/user assumption.
    assert concurrent_users_ceiling(112.0, 4, 0.01) == pytest.approx(2800.0)
    assert concurrent_users_ceiling(112.0, 6, 0.01) == pytest.approx(1866.666, rel=1e-4)


def test_concurrent_users_ceiling_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        concurrent_users_ceiling(112.0, 4, 0.0)
    with pytest.raises(ValueError):
        concurrent_users_ceiling(112.0, 0, 0.01)


def test_replica_mesh_pps_namenlos():
    # 4 replicas, each dialing the other 3, at LambdaR=0.02 events/ms.
    assert replica_mesh_pps(4, 0.02) == pytest.approx(240.0)


def test_replica_inbound_connections_namenlos():
    # 3 couriers + 3 other replicas = 6 inbound connections per replica.
    assert replica_inbound_connections(3, 4) == 6
