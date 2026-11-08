package heuristics

import "testing"

func TestDamerauLevenshtein(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{left: "google", right: "google", want: 0},
		{left: "gogle", right: "google", want: 1},
		{left: "googel", right: "google", want: 1},
		{left: "paypa1", right: "paypal", want: 1},
		{left: "abc", right: "xyz", want: 3},
		{left: "", right: "brand", want: 5},
	}
	for _, tt := range tests {
		t.Run(tt.left+"_"+tt.right, func(t *testing.T) {
			if got := damerauLevenshtein(tt.left, tt.right); got != tt.want {
				t.Fatalf("damerauLevenshtein(%q, %q) = %d, want %d", tt.left, tt.right, got, tt.want)
			}
		})
	}
}

func TestBrandDistanceConfusables(t *testing.T) {
	tests := []struct {
		candidate string
		brand     string
		wantDist  int
		wantTrans bool
	}{
		{candidate: "g00gle", brand: "google", wantDist: 0, wantTrans: true},
		{candidate: "paypa1", brand: "paypal", wantDist: 0, wantTrans: true},
		{candidate: "gogle", brand: "google", wantDist: 1, wantTrans: false},
		{candidate: "rnicrosoft", brand: "microsoft", wantDist: 0, wantTrans: true},
	}
	for _, tt := range tests {
		t.Run(tt.candidate, func(t *testing.T) {
			gotDist, gotTrans := brandDistance(tt.candidate, tt.brand)
			if gotDist != tt.wantDist || gotTrans != tt.wantTrans {
				t.Fatalf("brandDistance() = (%d, %v), want (%d, %v)", gotDist, gotTrans, tt.wantDist, tt.wantTrans)
			}
		})
	}
}

func TestUnicodeBrandDistance(t *testing.T) {
	distance, changed := unicodeBrandDistance("gοogle", "google")
	if distance != 0 || !changed {
		t.Fatalf("unicodeBrandDistance() = (%d, %v), want (0, true)", distance, changed)
	}
	if _, changed := unicodeBrandDistance("bücher", "google"); changed {
		t.Fatal("ordinary Unicode letters were treated as a confusable mapping")
	}
}
