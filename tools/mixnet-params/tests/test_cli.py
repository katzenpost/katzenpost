# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""CLI-level smoke tests for the mixnet-params command."""

from click.testing import CliRunner

from mixnet_params.cli import main


def test_default_invocation_runs_clean_and_prints_new_sections():
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 0, result.output
    assert "=== Sphinx packet geometry ===" in result.output
    assert "=== Replica MKEM (CTIDH) capacity ===" in result.output
    assert "=== Courier ↔ replica drain ===" in result.output


def test_layer_sizes_overrides_uniform_topology():
    result = CliRunner().invoke(main, ["--layer-sizes", "2,2,3"])
    assert result.exit_code == 0, result.output
    assert "layers: 2/2/3" in result.output
    assert "7 mix nodes" in result.output


def test_replica_ops_per_sec_multiplies_by_replica_count():
    result = CliRunner().invoke(
        main,
        ["--replicas", "4", "--replica-ops-per-sec", "28"],
    )
    assert result.exit_code == 0, result.output
    assert "System-wide CTIDH ops/sec (saturated; decoy traffic is free): 112.00" in result.output


def test_missing_user_pigeonhole_rate_prints_guidance_not_a_number():
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 0, result.output
    assert "Pass --user-pigeonhole-rate" in result.output
    assert "Concurrent users supported" not in result.output


def test_user_pigeonhole_rate_prints_concurrent_users():
    result = CliRunner().invoke(
        main,
        ["--replicas", "4", "--replica-ops-per-sec", "28", "--user-pigeonhole-rate", "0.01"],
    )
    assert result.exit_code == 0, result.output
    assert "Concurrent users supported" in result.output


def test_shard_k_option_no_longer_exists():
    result = CliRunner().invoke(main, ["--shard-k", "2"])
    assert result.exit_code != 0
    assert "no such option" in result.output.lower()
