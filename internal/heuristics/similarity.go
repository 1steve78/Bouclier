package heuristics

import "strings"

// brandDistance returns the smaller of the ordinary edit distance and a
// conservative ASCII confusable-normalized distance. The second result marks
// whether confusable normalization changed the candidate.
func brandDistance(candidate, brand string) (distance int, transformed bool) {
	candidate = strings.ToLower(candidate)
	brand = strings.ToLower(brand)
	normalized := normalizeBrandConfusables(candidate)
	transformed = normalized != candidate
	plainDistance := damerauLevenshtein(candidate, brand)
	confusableDistance := damerauLevenshtein(normalized, brand)
	if confusableDistance < plainDistance {
		return confusableDistance, transformed
	}
	return plainDistance, transformed
}

func normalizeBrandConfusables(value string) string {
	replacer := strings.NewReplacer(
		"0", "o",
		"1", "l",
		"3", "e",
		"4", "a",
		"5", "s",
		"7", "t",
		"rn", "m",
	)
	return replacer.Replace(value)
}

// unicodeBrandDistance applies a deliberately small set of common Greek and
// Cyrillic lookalikes. It is not a Unicode confusables database.
func unicodeBrandDistance(candidate, brand string) (distance int, changed bool) {
	candidate = strings.ToLower(candidate)
	brand = strings.ToLower(brand)
	normalized := strings.NewReplacer(
		"а", "a", // Cyrillic
		"е", "e",
		"о", "o",
		"р", "p",
		"с", "c",
		"х", "x",
		"у", "y",
		"і", "i",
		"ј", "j",
		"ӏ", "l",
		"ѕ", "s",
		"α", "a", // Greek
		"ο", "o",
		"ε", "e",
		"ρ", "p",
		"χ", "x",
		"ι", "i",
		"κ", "k",
		"τ", "t",
		"υ", "y",
	).Replace(candidate)
	changed = normalized != candidate
	return damerauLevenshtein(normalized, brand), changed
}

// damerauLevenshtein computes edit distance with adjacent transpositions.
// Inputs are ASCII hostname labels, so byte-wise comparison is intentional.
func damerauLevenshtein(left, right string) int {
	rows, columns := len(left)+1, len(right)+1
	distance := make([][]int, rows)
	for i := range distance {
		distance[i] = make([]int, columns)
		distance[i][0] = i
	}
	for j := 0; j < columns; j++ {
		distance[0][j] = j
	}
	for i := 1; i < rows; i++ {
		for j := 1; j < columns; j++ {
			cost := 0
			if left[i-1] != right[j-1] {
				cost = 1
			}
			distance[i][j] = min(
				distance[i-1][j]+1,
				distance[i][j-1]+1,
				distance[i-1][j-1]+cost,
			)
			if i > 1 && j > 1 && left[i-1] == right[j-2] && left[i-2] == right[j-1] {
				distance[i][j] = min(distance[i][j], distance[i-2][j-2]+1)
			}
		}
	}
	return distance[len(left)][len(right)]
}
