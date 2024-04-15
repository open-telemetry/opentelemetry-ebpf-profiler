/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

// hasProbeReadBug returns true if the given Linux kernel version is affected by
// a bug that can lead to system freezes.
func hasProbeReadBug(major, minor, patch uint32) bool {
	if major == 5 && minor >= 19 {
		return true
	} else if major == 6 {
		switch minor {
		case 0, 2:
			return true
		case 1:
			// The bug fix was backported to the LTS kernel 6.1.36 with
			// nolint:lll
			// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/mm/maccess.c?h=v6.1.36&id=2e7ad879e1b0256fb9e4703fd6cd2864d707dea7
			if patch < 36 {
				return true
			}
			return false
		case 3:
			// The bug fix was backported to the LTS kernel 6.3.10 with
			// nolint:lll
			// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/mm/maccess.c?h=v6.3.10&id=3acb3dd3145b54933e88ae107e1288c1147d6d33
			if patch < 10 {
				return true
			}
			return false
		default:
			// The bug fix landed in 6.4 with
			// nolint:lll
			// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/mm/maccess.c?h=v6.4&id=d319f344561de23e810515d109c7278919bff7b0
			// So newer versions of the Linux kernel are not affected.
			return false
		}
	}
	// Other Linux kernel versions, like 4.x, are not affected by this bug.
	return false
}
