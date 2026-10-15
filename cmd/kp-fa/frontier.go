// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import "math"

func findFrontier(exists func(uint64) (bool, error)) (uint64, error) {
	lo, hi := uint64(0), uint64(1)
	for {
		ok, err := exists(hi)
		if err != nil {
			return 0, err
		}
		if !ok {
			break
		}
		lo = hi
		if hi > math.MaxUint64/2 {
			return lo, nil
		}
		hi *= 2
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		ok, err := exists(mid)
		if err != nil {
			return 0, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

func startBox(frontier, back uint64, fromStart, ended bool) uint64 {
	if fromStart || back >= frontier || ended && back == 0 {
		return 1
	}
	return frontier - back
}
