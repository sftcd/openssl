package main

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
)

type suiteConfig struct {
	kem hpke.KEM
	kdf hpke.KDF
	aead hpke.AEAD
	name string
	genKey func() (hpke.PrivateKey, []byte, []byte, error)
	pubFromBytes func([]byte) (hpke.PublicKey, error)
	privFromBytes func([]byte) (hpke.PrivateKey, error)
}

func dhkemSuite(curve ecdh.Curve, name string) suiteConfig {
	return suiteConfig {
		kem: hpke.DHKEM(curve),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: name,

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			ecdhPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewDHKEMPrivateKey(ecdhPriv)
			if err != nil {
				return nil, nil, nil, err
			}
			privBytes, err := priv.Bytes()
			if err != nil {
				return nil, nil, nil, err
			}
			return priv, privBytes, priv.PublicKey().Bytes(), nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			pub, err := curve.NewPublicKey(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewDHKEMPublicKey(pub)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			priv, err := curve.NewPrivateKey(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewDHKEMPrivateKey(priv)
		},
	}
}

//Go HPKE has no ML-KEM 512 suite

func mlkem768Suite() suiteConfig {
	return suiteConfig {
		kem: hpke.MLKEM768(),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: "ML-KEM-768",

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewMLKEMPrivateKey(dk)
			if err != nil {
				return nil, nil, nil, err
			}
			return priv, dk.Bytes(), priv.PublicKey().Bytes(), nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			ek, err := mlkem.NewEncapsulationKey768(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewMLKEMPublicKey(ek)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			dk, err := mlkem.NewDecapsulationKey768(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewMLKEMPrivateKey(dk)
		},
	}
}

func mlkem1024Suite() suiteConfig {
	return suiteConfig {
		kem: hpke.MLKEM1024(),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: "ML-KEM-1024",

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewMLKEMPrivateKey(dk)
			if err != nil {
				return nil, nil, nil, err
			}
			return priv, dk.Bytes(), priv.PublicKey().Bytes(), nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			ek, err := mlkem.NewEncapsulationKey1024(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewMLKEMPublicKey(ek)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			dk, err := mlkem.NewDecapsulationKey1024(b)
			if err != nil {
				return nil, err
			}
			return hpke.NewMLKEMPrivateKey(dk)
		},
	}
}

func xwingSuite() suiteConfig {
	const mlkemEKSize = 1184
	const mlkemSeedSize = 64

	return suiteConfig {
		kem: hpke.MLKEM768X25519(),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: "XWING (MLKEM768+X25519)",

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			mlkemDK, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, nil, err
			}
			ecdhPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewHybridPrivateKey(mlkemDK, ecdhPriv)
			if err != nil {
				return nil, nil, nil, err
			}
			privBytes := append(mlkemDK.Bytes(), ecdhPriv.Bytes()...)
			pubBytes := append(mlkemDK.EncapsulationKey().Bytes(), ecdhPriv.PublicKey().Bytes()...)
			return priv, privBytes, pubBytes, nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			ek, err := mlkem.NewEncapsulationKey768(b[:mlkemEKSize])
			if err != nil {
				return nil, err
			}
			tPub, err := ecdh.X25519().NewPublicKey(b[mlkemEKSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPublicKey(ek, tPub)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			dk, err := mlkem.NewDecapsulationKey768(b[:mlkemSeedSize])
			if err != nil {
				return nil, err
			}
			ecdhPriv, err := ecdh.X25519().NewPrivateKey(b[mlkemSeedSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPrivateKey(dk, ecdhPriv)
		},
	}
}

func mlkem768P256Suite() suiteConfig {
	const mlkemEKSize = 1184
	const mlkemSeedSize = 64

	return suiteConfig {
		kem: hpke.MLKEM768P256(),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: "MLKEM768-P256",

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			mlkemDK, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, nil, err
			}
			ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewHybridPrivateKey(mlkemDK, ecdhPriv)
			if err != nil {
				return nil, nil, nil, err
			}
			privBytes := append(mlkemDK.Bytes(), ecdhPriv.Bytes()...)
			pubBytes := append(mlkemDK.EncapsulationKey().Bytes(), ecdhPriv.PublicKey().Bytes()...)
			return priv, privBytes, pubBytes, nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			ek, err := mlkem.NewEncapsulationKey768(b[:mlkemEKSize])
			if err != nil {
				return nil, err
			}
			tPub, err := ecdh.P256().NewPublicKey(b[mlkemEKSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPublicKey(ek, tPub)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			dk, err := mlkem.NewDecapsulationKey768(b[:mlkemSeedSize])
			if err != nil {
				return nil, err
			}
			ecdhPriv, err := ecdh.P256().NewPrivateKey(b[mlkemSeedSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPrivateKey(dk, ecdhPriv)
		},
	}
}

func mlkem1024P384Suite() suiteConfig {
	const mlkemEKSize = 1568
	const mlkemSeedSize = 64

	return suiteConfig {
		kem: hpke.MLKEM1024P384(),
		kdf: hpke.HKDFSHA256(),
		aead: hpke.AES128GCM(),
		name: "MLKEM1024-P384",

		genKey: func() (hpke.PrivateKey, []byte, []byte, error) {
			mlkemDK, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, nil, nil, err
			}
			ecdhPriv, err := ecdh.P384().GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, nil, err
			}
			priv, err := hpke.NewHybridPrivateKey(mlkemDK, ecdhPriv)
			if err != nil {
				return nil, nil, nil, err
			}
			privBytes := append(mlkemDK.Bytes(), ecdhPriv.Bytes()...)
			pubBytes := append(mlkemDK.EncapsulationKey().Bytes(), ecdhPriv.PublicKey().Bytes()...)
			return priv, privBytes, pubBytes, nil
		},

		pubFromBytes: func(b []byte) (hpke.PublicKey, error) {
			ek, err := mlkem.NewEncapsulationKey1024(b[:mlkemEKSize])
			if err != nil {
				return nil, err
			}
			tPub, err := ecdh.P384().NewPublicKey(b[mlkemEKSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPublicKey(ek, tPub)
		},

		privFromBytes: func(b []byte) (hpke.PrivateKey, error) {
			dk, err := mlkem.NewDecapsulationKey1024(b[:mlkemSeedSize])
			if err != nil {
				return nil, err
			}
			ecdhPriv, err := ecdh.P384().NewPrivateKey(b[mlkemSeedSize:])
			if err != nil {
				return nil, err
			}
			return hpke.NewHybridPrivateKey(dk, ecdhPriv)
		},
	}
}

func suiteFor(name string) (suiteConfig, error) {
	switch name {
	case "x25519":
		return dhkemSuite(ecdh.X25519(), "X25519"), nil
	case "p256":
		return dhkemSuite(ecdh.P256(), "P-256"), nil
	case "mlkem768":
		return mlkem768Suite(), nil
	case "mlkem1024":
		return mlkem1024Suite(), nil
	case "xwing":
		return xwingSuite(), nil
	case "mlkem768p256":
		return mlkem768P256Suite(), nil
	case "mlkem1024p384":
		return mlkem1024P384Suite(), nil
	default:
		return suiteConfig{}, fmt.Errorf(
			"unknown suite", name)
	}
}

const goPlaintext = "Hello from Go HPKE!!!"

var info = []byte("hpke-interop-test")

func makeAAD(suiteName string) []byte {
	return []byte("hpke-interop-test " + suiteName + " kdf=HKDF-SHA256 aead=AES-128-GCM")
}

func keygen(s suiteConfig) error {
	_, privBytes, pubBytes, err := s.genKey()
	if err != nil {
		return fmt.Errorf("genKey: %w", err)
	}

	if err := os.WriteFile("go_recipient.pub", pubBytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile("go_recipient.priv", privBytes, 0600); err != nil {
		return err
	}

	fmt.Printf("keygen: suite = %s\n", s.name)
	fmt.Printf("go_recipient.pub (%d bytes)\n", len(pubBytes))
	fmt.Printf("go_recipient.priv (%d bytes)\n", len(privBytes))
	return nil
}

func encrypt(s suiteConfig) error {
	aad := makeAAD(s.name)

	pubBytes, err := os.ReadFile("c_recipient.pub")
	if err != nil {
		return fmt.Errorf("read c_recipient.pub: %w", err)
	}

	recPub, err := s.pubFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("parse c_recipient.pub: %w", err)
	}

	enc, sender, err := hpke.NewSender(recPub, s.kdf, s.aead, info)
	if err != nil {
		return fmt.Errorf("NewSender: %w", err)
	}

	ct, err := sender.Seal(aad, []byte(goPlaintext))
	if err != nil {
		return fmt.Errorf("Seal: %w", err)
	}

	if err := os.WriteFile("c_enc.bin", enc, 0644); err != nil {
		return err
	}

	if err := os.WriteFile("c_ct.bin", ct, 0644); err != nil {
		return err
	}

	fmt.Printf("encrypt: suite = %s\n", s.name)
	fmt.Printf("encrypt: plaintext = %q\n", goPlaintext)
	fmt.Printf("enc (%d bytes) -> c_enc.bin\n", len(enc))
	fmt.Printf("ct (%d bytes) -> c_ct.bin\n", len(ct))
	return nil
}

func decrypt(s suiteConfig) error {
	aad := makeAAD(s.name)

	privBytes, err := os.ReadFile("go_recipient.priv")
	if err != nil {
		return fmt.Errorf("read go_recipient.priv: %w", err)
	}

	enc, err := os.ReadFile("go_enc.bin")
	if err != nil {
		return fmt.Errorf("read go_enc.bin: %w", err)
	}

	ct, err := os.ReadFile("go_ct.bin")
	if err != nil {
		return fmt.Errorf("read go_ct.bin: %w", err)
	}

	recPriv, err := s.privFromBytes(privBytes)
	if err != nil {
		return fmt.Errorf("parse go_recipient.priv: %w", err)
	}

	receiver, err := hpke.NewRecipient(enc, recPriv, s.kdf, s.aead, info)
	if err != nil {
		return fmt.Errorf("NewRecipient (decap failed): %w", err)
	}

	plaintext, _ := receiver.Open(aad, ct)

	fmt.Printf("decrypt: suite = %s\n", s.name)
	fmt.Printf("enc (%d bytes)\n", len(enc))
	fmt.Printf("ct (%d bytes)\n", len(ct))
	fmt.Printf("plaintext = %q\n", string(plaintext))
	fmt.Printf("decrypt: success - C encrypted to Go's public key, Go decrypted\n")
	return nil
}

func main() {
	suiteFlag := flag.String("suite", "x25519", "KEM suite: x25519 | p256 | mlkem768 | mlkem1024 | xwing | mlkem768p256 | mlkem1024p384")
	flag.Parse()

	s, err := suiteFor(*suiteFlag)

	cmd := flag.Arg(0)
	switch cmd {
	case "keygen":
		err = keygen(s)
	case "encrypt":
		err = encrypt(s)
	case "decrypt":
		err = decrypt(s)
	default:
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
