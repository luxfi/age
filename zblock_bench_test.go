package age

// Throwaway per-block crypto microbench (scientist). Quantifies the cost
// of vfs's per-4KiB-block age encryption vs a single whole-stream age
// frame, for X25519 / ML-KEM-768-hybrid / X-Wing.
//   GOWORK=off CGO_ENABLED=0 go test -run TestZBlockCrypto -v -timeout 20m

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"
)

const zBlock = 4096

type zScheme struct {
	name string
	rec  Recipient
	id   Identity
}

func zSchemes(t *testing.T) []zScheme {
	x, err := GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	w, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return []zScheme{
		{"x25519", x.Recipient(), x},
		{"mlkem768-hybrid", h.Recipient(), h},
		{"xwing", w.Recipient(), w},
	}
}

func zEncBlock(rec Recipient, pt []byte) []byte {
	var buf bytes.Buffer
	w, _ := Encrypt(&buf, rec)
	w.Write(pt)
	w.Close()
	return buf.Bytes()
}

func TestZBlockCrypto(t *testing.T) {
	pt := make([]byte, zBlock)
	rand.Read(pt)
	iters := 2000

	fmt.Printf("\n=== per-4KiB-block age crypto (M1 Max, single core) ===\n")
	fmt.Printf("%-18s %10s %10s %12s %12s %10s\n", "scheme", "enc_us", "dec_us", "ct_bytes", "overhead", "dec_MB/s")
	for _, s := range zSchemes(t) {
		ct := zEncBlock(s.rec, pt)

		// warm
		for i := 0; i < 50; i++ {
			zEncBlock(s.rec, pt)
		}
		t0 := time.Now()
		for i := 0; i < iters; i++ {
			_ = zEncBlock(s.rec, pt)
		}
		encUs := float64(time.Since(t0).Microseconds()) / float64(iters)

		for i := 0; i < 50; i++ {
			r, _ := Decrypt(bytes.NewReader(ct), s.id)
			io.Copy(io.Discard, r)
		}
		t1 := time.Now()
		for i := 0; i < iters; i++ {
			r, err := Decrypt(bytes.NewReader(ct), s.id)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, r)
		}
		decUs := float64(time.Since(t1).Microseconds()) / float64(iters)

		overhead := len(ct) - zBlock
		decMBps := (float64(zBlock) / 1e6) / (decUs / 1e6)
		fmt.Printf("%-18s %10.1f %10.1f %12d %12d %10.1f\n",
			s.name, encUs, decUs, len(ct), overhead, decMBps)
	}

	// Project per-block decrypt cost to restore scales (single-threaded).
	fmt.Printf("\n=== projected SEQUENTIAL per-block decrypt wall-time (single core) ===\n")
	fmt.Printf("%-18s %14s %14s\n", "scheme", "1GB(262144blk)", "8.5GB(2.23Mblk)")
	pt2 := make([]byte, zBlock)
	rand.Read(pt2)
	for _, s := range zSchemes(t) {
		ct := zEncBlock(s.rec, pt2)
		n := 500
		t1 := time.Now()
		for i := 0; i < n; i++ {
			r, _ := Decrypt(bytes.NewReader(ct), s.id)
			io.Copy(io.Discard, r)
		}
		decS := time.Since(t1).Seconds() / float64(n)
		blk1 := float64(1<<30) / zBlock
		blk8 := float64(8.5*(1<<30)) / zBlock
		fmt.Printf("%-18s %14s %14s\n", s.name,
			time.Duration(decS*blk1*float64(time.Second)).Round(time.Second),
			time.Duration(decS*blk8*float64(time.Second)).Round(time.Second))
	}
}

func TestZStreamCrypto(t *testing.T) {
	// Whole-stream alternative: ONE age frame over a large payload, the
	// way Replicator.Restore (replicate.go) streams a snapshot — one KEM,
	// then ChaCha20 over the whole thing.
	sizeMB := 256
	payload := make([]byte, sizeMB<<20)
	rand.Read(payload)
	fmt.Printf("\n=== whole-stream age decrypt (one frame over %dMB) ===\n", sizeMB)
	fmt.Printf("%-18s %12s %12s\n", "scheme", "dec_wall", "dec_MB/s")
	for _, s := range zSchemes(t) {
		var enc bytes.Buffer
		w, _ := Encrypt(&enc, s.rec)
		w.Write(payload)
		w.Close()
		ct := enc.Bytes()

		t0 := time.Now()
		r, err := Decrypt(bytes.NewReader(ct), s.id)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, r)
		el := time.Since(t0)
		fmt.Printf("%-18s %12s %12.1f\n", s.name, el.Round(time.Millisecond),
			float64(n)/1e6/el.Seconds())
	}
}
