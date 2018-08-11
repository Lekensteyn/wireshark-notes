// Queries the supported TLS versions from a server.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	recordTypeAlert     uint8 = 21
	recordTypeHandshake uint8 = 22

	handshakeTypeClientHello       uint8 = 1
	handshakeTypeServerHello       uint8 = 2
	handshakeTypeHelloRetryRequest uint8 = 6 // up to draft -21

	versionTLS10        uint16 = 0x301
	versionTLS11        uint16 = 0x302
	versionTLS12        uint16 = 0x303
	versionTLS13DraftXX uint16 = 0x7f00
	versionTLS13Draft01 uint16 = versionTLS13DraftXX | 1
	versionTLS13Draft21 uint16 = versionTLS13DraftXX | 21
	versionTLS13Draft28 uint16 = versionTLS13DraftXX | 28
	versionTLS13        uint16 = 0x304

	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_AES_128_GCM_SHA256                  uint16 = 0x1301
	TLS_AES_256_GCM_SHA384                  uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256            uint16 = 0x1303
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f

	extServerName          uint16 = 0
	extSupportedGroups     uint16 = 10
	extSignatureAlgorithms uint16 = 13
	extKeySharePre23       uint16 = 40
	extSupportedVersions   uint16 = 43
	extKeyShare            uint16 = 51

	curveSECP256r1 uint16 = 0x0017
	curveX25519    uint16 = 0x001d

	PKCS1WithSHA256        uint16 = 0x0401
	PSSWithSHA256          uint16 = 0x0804
	ECDSAWithP256AndSHA256 uint16 = 0x0403
)

func addExtension(b *cryptobyte.Builder, extType uint16, f cryptobyte.BuilderContinuation) {
	b.AddUint16(extType)
	b.AddUint16LengthPrefixed(f)
}

func buildClientHelloRecord(host string, minVersion, maxVersion uint16) ([]byte, error) {
	var b cryptobyte.Builder

	if minVersion > maxVersion && maxVersion != versionTLS13 {
		panic("failed: minVersion <= maxVersion")
	}

	// Record header
	b.AddUint8(recordTypeHandshake)
	b.AddUint16(versionTLS10)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		// Handshake header
		b.AddUint8(handshakeTypeClientHello)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			// ClientHello
			b.AddUint16(versionTLS12)
			clientRandom := make([]byte, 32)
			b.AddBytes(clientRandom)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				sid := make([]byte, 32)
				b.AddBytes(sid)
			})
			// Cipher suites
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				cipherSuites := []uint16{
					// MTI TLS 1.3 suites
					TLS_AES_128_GCM_SHA256,
					TLS_AES_256_GCM_SHA384,
					TLS_CHACHA20_POLY1305_SHA256,
					// modern TLS 1.2 suites
					TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					// MTI TLS 1.2 suite
					TLS_RSA_WITH_AES_128_CBC_SHA,
				}
				for _, cipherSuite := range cipherSuites {
					b.AddUint16(cipherSuite)
				}
			})
			// Add NULL compression
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0)
			})
			// Extensions
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				addExtension(b, extSupportedVersions, func(b *cryptobyte.Builder) {
					// Advertise all draft versions
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						for i := maxVersion; i >= minVersion; i -= 1 {
							b.AddUint16(i)
						}
						if maxVersion == versionTLS13 {
							b.AddUint16(versionTLS13)
						}
						// if this is not added, TLS 1.3
						// implementations that do not
						// want to negotiate 1.3 fail
						// even if 1.2 is acceptable.
						b.AddUint16(versionTLS12)
					})
				})
				addExtension(b, extServerName, func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							sniHostName := []byte(host)
							b.AddBytes(sniHostName)
						})
					})
				})
				addExtension(b, extKeySharePre23, func(b *cryptobyte.Builder) {
					// empty client_shares
					b.AddUint16(0)
				})
				addExtension(b, extKeyShare, func(b *cryptobyte.Builder) {
					// empty client_shares
					b.AddUint16(0)
				})
				addExtension(b, extSupportedGroups, func(b *cryptobyte.Builder) {
					// Advertise MTI groups
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(curveSECP256r1)
						b.AddUint16(curveX25519)
					})
				})
				addExtension(b, extSignatureAlgorithms, func(b *cryptobyte.Builder) {
					// Advertise MTI signature algorithms
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(PKCS1WithSHA256)
						b.AddUint16(PSSWithSHA256)
						b.AddUint16(ECDSAWithP256AndSHA256)
					})
				})
			})
		})
	})
	return b.Bytes()
}

func parseServerHelloHandshake(recordFragment cryptobyte.String) (uint16, error) {
	var hsType uint8
	var hs cryptobyte.String
	if !recordFragment.ReadUint8(&hsType) ||
		!recordFragment.ReadUint24LengthPrefixed(&hs) {
		return 0, errors.New("bad hs msg")
	}
	switch hsType {
	case handshakeTypeServerHello:
		var version uint16
		if !hs.ReadUint16(&version) {
			return 0, errors.New("SH too short")
		}
		// pre-TLS 1.3 or up to draft -21
		if version != versionTLS12 {
			return version, nil
		}
		// from draft -21 and up, look for supported_versions extension
		var sid cryptobyte.String
		if !hs.Skip(32) ||
			!hs.ReadUint8LengthPrefixed(&sid) ||
			// skip cipher, comp method
			!hs.Skip(2+1) {
			return 0, errors.New("invalid SH")
		}
		// parse (in TLS 1.2 optional) SH extensions
		if !hs.Empty() {
			hs.Skip(2)
			for !hs.Empty() {
				var extType uint16
				var extData cryptobyte.String
				if !hs.ReadUint16(&extType) ||
					!hs.ReadUint16LengthPrefixed(&extData) {
					return 0, errors.New("Invalid extension")
				}
				if extType == extSupportedVersions {
					if !extData.ReadUint16(&version) {
						return 0, errors.New("Invalid SV extension")
					}
					// accept version
					break
				}
			}
		}
		return version, nil

	case handshakeTypeHelloRetryRequest: // draft -21 and before
		var version uint16
		if !hs.ReadUint16(&version) {
			return 0, errors.New("HRR too short")
		}
		return version, nil

	default:
		return 0, errors.New("unexpected hs msg")
	}
}

func parseServerHelloRecord(buffer []byte) (uint16, error) {
	s := cryptobyte.String(buffer)
	var recordType uint8
	var recordVersion uint16
	var recordFragment cryptobyte.String
	if !s.ReadUint8(&recordType) ||
		!s.ReadUint16(&recordVersion) ||
		!s.Skip(2) {
		return 0, errors.New("bad record")
	}
	// do not read whole record as it may contain multiple HS messages
	recordFragment = s

	switch recordType {
	case recordTypeHandshake:
		return parseServerHelloHandshake(recordFragment)
	case recordTypeAlert:
		var alertLevel, alertDescription uint8
		if recordFragment.ReadUint8(&alertLevel) && recordFragment.ReadUint8(&alertDescription) {
			alertLevelStr := "unknown"
			switch alertLevel {
			case 1:
				alertLevelStr = "warning"
			case 2:
				alertLevelStr = "fatal"
			}
			return 0, fmt.Errorf("%s alert message - %d", alertLevelStr, alertDescription)
		}
		return 0, errors.New("unexpected alert message")
	default:
		return 0, errors.New("unexpected record type")
	}
}

func versionToString(version uint16) string {
	switch version {
	case versionTLS10:
		return "TLS 1.0"
	case versionTLS11:
		return "TLS 1.1"
	case versionTLS12:
		return "TLS 1.2"
	case versionTLS13:
		return "TLS 1.3"
	default:
		if (version & versionTLS13DraftXX) == versionTLS13DraftXX {
			return fmt.Sprintf("TLS 1.3 (draft %d)", version&0xff)
		}
		return fmt.Sprintf("unknown %#x", version)
	}
}

func queryVersion(address, sniHost string, minVersion, maxVersion uint16) (uint16, error) {
	clientHello, err := buildClientHelloRecord(sniHost, minVersion, maxVersion)
	if err != nil {
		return 0, err
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.Write(clientHello)
	// read record (not perfect, it assumes one message in a single packet)
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if n == 0 && err != nil {
		return 0, err
	}
	return parseServerHelloRecord(buffer)
}

func main() {
	var address string
	flag.StringVar(&address, "connect", "localhost", "hostname[:port] to connect to")
	flag.Parse()

	if !strings.Contains(address, ":") {
		address += ":443"
	}

	sniHost, _, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}

	// prepare client hello
	minVersion := versionTLS13Draft01
	maxVersion := versionTLS13
	for minVersion <= maxVersion || maxVersion == versionTLS13 {
		version, err := queryVersion(address, sniHost, minVersion, maxVersion)
		if err != nil {
			fmt.Printf("%s query (max version: %s) failed: %s\n", address, versionToString(maxVersion), err)
			break
		}
		fmt.Printf("%s version: %#x - %s\n", address, version, versionToString(version))
		if maxVersion == versionTLS13 {
			maxVersion = versionTLS13Draft28
		} else {
			maxVersion = version - 1
		}
	}
}
