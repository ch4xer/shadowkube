package baseline

import (
	"github.com/agnivade/levenshtein"
)

func getDistance(s1, s2 string) int {
    return levenshtein.ComputeDistance(s1, s2)
}

func getDiffRatio(base, target string) float64 {
    return float64(getDistance(base, target)) / float64(len(base))
}

