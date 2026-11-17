package tls

import (
	stdtls "crypto/tls"
	"net"
	"slices"
	"testing"
)

func randomizedKeyShareGroups(spec ClientHelloSpec) (curves, shares []CurveID) {
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *SupportedCurvesExtension:
			curves = extension.Curves
		case *KeyShareExtension:
			for _, share := range extension.KeyShares {
				shares = append(shares, share.Group)
			}
		}
	}
	return
}

// A randomized hello carries an X25519MLKEM768 key share exactly when it
// advertises the group, and never sends a key share for an unadvertised group.
func TestRandomizedSpecHybridKeyShare(t *testing.T) {
	t.Parallel()
	weightSets := map[string]*Weights{"default": &DefaultWeights}
	tls13 := DefaultWeights
	tls13.TLSVersMax_Set_VersionTLS13 = 1
	tls13.FirstKeyShare_Set_CurveP256 = 0
	weightSets["tls13"] = &tls13
	p256 := DefaultWeights
	p256.TLSVersMax_Set_VersionTLS13 = 1
	p256.FirstKeyShare_Set_CurveP256 = 1
	weightSets["p256-first"] = &p256
	for name, weights := range weightSets {
		var advertised, withheld int
		for range 2000 {
			seed, err := NewPRNGSeed()
			if err != nil {
				t.Fatal(err)
			}
			id := HelloRandomized
			id.Seed = seed
			id.Weights = weights
			spec, err := generateRandomizedSpec(&id, "example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			curves, shares := randomizedKeyShareGroups(spec)
			for _, group := range shares {
				if !slices.Contains(curves, group) {
					t.Fatalf("%s: key share for unadvertised group %v (curves %v)", name, group, curves)
				}
			}
			if slices.Contains(curves, X25519MLKEM768) {
				advertised++
				if !slices.Contains(shares, X25519MLKEM768) {
					t.Fatalf("%s: X25519MLKEM768 advertised without key share (shares %v)", name, shares)
				}
			} else {
				withheld++
			}
		}
		if name != "default" && (advertised == 0 || withheld == 0) {
			t.Fatalf("%s: hybrid group never varied: advertised=%d withheld=%d", name, advertised, withheld)
		}
	}
}

// crypto/tls servers prefer X25519MLKEM768; a randomized hello must complete
// against one for any seed instead of failing on a HelloRetryRequest.
func TestRandomizedHandshakeHybridPreferringServer(t *testing.T) {
	t.Parallel()
	serverConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{{
			Certificate: [][]byte{testRSACertificate},
			PrivateKey:  testRSAPrivateKey,
		}},
		CurvePreferences: []stdtls.CurveID{stdtls.CurveID(X25519MLKEM768), stdtls.X25519, stdtls.CurveP256, stdtls.CurveP384},
	}
	weights := DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	for i := range 200 {
		seed, err := NewPRNGSeed()
		if err != nil {
			t.Fatal(err)
		}
		id := HelloRandomized
		id.Seed = seed
		id.Weights = &weights
		clientConn, serverConn := net.Pipe()
		serverDone := make(chan error, 1)
		go func() {
			server := stdtls.Server(serverConn, serverConfig)
			err := server.Handshake()
			// close the raw pipe: a TLS close_notify would block on the
			// synchronous pipe while the peer writes its own
			serverConn.Close()
			serverDone <- err
		}()
		client := UClient(clientConn, &Config{ServerName: "example.golang", InsecureSkipVerify: true}, id)
		clientErr := client.Handshake()
		clientConn.Close()
		serverErr := <-serverDone
		if clientErr != nil {
			t.Fatalf("seed %d: client handshake: %v", i, clientErr)
		}
		if serverErr != nil {
			t.Fatalf("seed %d: server handshake: %v", i, serverErr)
		}
	}
}
