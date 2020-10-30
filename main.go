package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/cloudflare/cfssl/helpers"

	"github.com/urfave/cli"
)

// Extension
var (
	oidMicrosoftCertSrv                      = []int{1, 3, 6, 1, 4, 1, 311, 21, 1}
	oidMicrosoftPreviousCertHash             = []int{1, 3, 6, 1, 4, 1, 311, 21, 2}
	oidMicrosoftCertificateTemplate          = []int{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidMicrsoftApplicationPolicies           = []int{1, 3, 6, 1, 4, 1, 311, 21, 10}
	oidExtensionAuthorityInfoAccess          = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionLogotype                     = []int{1, 3, 6, 1, 5, 5, 7, 1, 12}
	oidExtensionSubjectKeyID                 = []int{2, 5, 29, 14}
	oidExtensionKeyUsage                     = []int{2, 5, 29, 15}
	oidExtensionSubjectAltName               = []int{2, 5, 29, 17}
	oidExtensionBasicConstraints             = []int{2, 5, 29, 19}
	oidExtensionNameConstraints              = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints        = []int{2, 5, 29, 31}
	oidExtensionCertificatePolicies          = []int{2, 5, 29, 32}
	oidExtensionAuthorityKeyID               = []int{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage             = []int{2, 5, 29, 37}
	oidExtensionNSCertType                   = []int{2, 16, 840, 1, 113730, 1, 1}
	oidExtensionNSBaseURL                    = []int{2, 16, 840, 1, 113730, 1, 2}
	oidExtensionNSRevocationURL              = []int{2, 16, 840, 1, 113730, 1, 3}
	oidExtensionNSCARevocationURL            = []int{2, 16, 840, 1, 113730, 1, 4}
	oidExtensionNSRenewalURL                 = []int{2, 16, 840, 1, 113730, 1, 7}
	oidExtensionNSCAPolicyURL                = []int{2, 16, 840, 1, 113730, 1, 8}
	oidExtensionNSSSLServerName              = []int{2, 16, 840, 1, 113730, 1, 12}
	oidExtensionNSCertificateComment         = []int{2, 16, 840, 1, 113730, 1, 13}
	oidExtKeyUsageAny                        = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtBasicConstraints                   = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsageServerAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto  = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
)

// Key Usage
var keyUsages = []string{
	"digital signature",
	"content commitment",
	"key encipherment",
	"data encipherment",
	"key agreement",
	"certificate signing",
	"CRL signing",
	"encipher only",
	"decipher only",
}

// AuthorityKeyID RFC 5280,  4.2.1.1
type AuthorityKeyID struct {
	ID           []byte        `asn1:"optional,tag:0"`
	Issuer       asn1.RawValue `asn1:"optional,tag:1"`
	SerialNumber *big.Int      `asn1:"optional,tag:2"`
}

// DumpName asdad
func DumpName(name pkix.Name, pad int) {
	var pads = strings.Repeat("  ", pad)
	var names = [][]string{}
	if len(name.CommonName) > 0 {
		names = append(names, []string{"common name", name.CommonName})
	}
	for _, v := range name.Country {
		names = append(names, []string{"country", v})
	}
	for _, v := range name.Locality {
		names = append(names, []string{"locality", v})
	}
	for _, v := range name.Province {
		names = append(names, []string{"province", v})
	}
	for _, v := range name.StreetAddress {
		names = append(names, []string{"street address", v})
	}
	for _, v := range name.PostalCode {
		names = append(names, []string{"postal code", v})
	}
	for _, v := range name.Organization {
		names = append(names, []string{"organization", v})
	}
	for _, v := range name.OrganizationalUnit {
		names = append(names, []string{"organizational unit", v})
	}
	for _, a := range name.Names {
		if v, ok := a.Value.(string); ok {
			names = append(names, []string{attributeName(a.Type), v})
		}
	}

	var nsize = 0
	for _, name := range names {
		if len(name[0]) > nsize {
			nsize = len(name[0]) + 1
		}
	}
	var format = fmt.Sprintf("%%s%%-%ds %%s\n", nsize)
	for _, name := range names {
		fmt.Printf(format, pads, strings.Title(name[0])+":", name[1])
	}
}

// DumpGeneralNames
func DumpGeneralNames(seq asn1.RawValue, pad int) {
	var pads = strings.Repeat("  ", pad)
	var err error
	if seq.IsCompound {
		rest := seq.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				break
			}
			switch v.Tag {
			case 1:
				fmt.Printf("%sEmail: %s\n", pads, string(v.Bytes))
			case 2:
				fmt.Printf("%sDNS: %s\n", pads, string(v.Bytes))
			case 4:
				fmt.Printf("%sDirectory:\n", pads)
				var rdns = &pkix.RDNSequence{}
				if _, err = asn1.Unmarshal(v.Bytes, rdns); err == nil {
					var name = &pkix.Name{}
					name.FillFromRDNSequence(rdns)
					DumpName(*name, pad+1)
				} else {
					fmt.Printf("%s  error: %v\n", pads, err)
				}
			case 6:
				fmt.Printf("%sURI: %s\n", pads, string(v.Bytes))
			case 7:
				switch len(v.Bytes) {
				case net.IPv4len:
					fmt.Printf("%sIPv4: %s\n", pads, &net.IPAddr{
						IP:   v.Bytes,
						Zone: "ip4",
					})
				case net.IPv6len:
					fmt.Printf("%sIPv6: %s\n", pads, &net.IPAddr{
						IP:   v.Bytes,
						Zone: "ip6",
					})
				}
			case 8:
				var oid asn1.ObjectIdentifier
				fmt.Printf("%sRegistered ID:\n", pads)
				if _, err = asn1.Unmarshal(v.Bytes, &oid); err == nil {
					DumpOID(oid, pad+1)
				} else {
					fmt.Printf("%s  error: %v\n", pads, err)
				}
			default:
				fmt.Printf("%sUnknown: tag %d, class %d\n", pads, v.Tag, v.Class)
			}
		}
	} else {
		fmt.Printf("%sUnknown compound=%t, tag=%d, class=%d\n", pads, seq.IsCompound, seq.Tag, seq.Class)
	}
}

var attributeNameMap = map[string]string{
	"0.9.2342.19200300.100.1.1":  "user ID",
	"0.9.2342.19200300.100.1.2":  "address",
	"0.9.2342.19200300.100.1.3":  "mailbox",
	"0.9.2342.19200300.100.1.4":  "info",
	"0.9.2342.19200300.100.1.5":  "favourite drink",
	"0.9.2342.19200300.100.1.6":  "room number",
	"0.9.2342.19200300.100.1.8":  "user class",
	"0.9.2342.19200300.100.1.9":  "host",
	"0.9.2342.19200300.100.1.10": "manager",
	"0.9.2342.19200300.100.1.11": "document identifier",
	"0.9.2342.19200300.100.1.12": "document title",
	"0.9.2342.19200300.100.1.13": "document version",
	"0.9.2342.19200300.100.1.14": "document author",
	"0.9.2342.19200300.100.1.15": "document location",
	"0.9.2342.19200300.100.1.25": "domain component",
	"0.9.2342.19200300.100.1.26": "a record",
	"0.9.2342.19200300.100.1.27": "md record",
	"0.9.2342.19200300.100.1.28": "mx record",
	"0.9.2342.19200300.100.1.29": "ns record",
	"0.9.2342.19200300.100.1.30": "soa record",
	"0.9.2342.19200300.100.1.31": "cname record",
	"0.9.2342.19200300.100.1.42": "pager",
	"0.9.2342.19200300.100.1.44": "uniqueidentifier",
	"1.2.840.113549.1.9.1":       "e-mail address",
	"1.2.840.113549.1.9.2":       "unstructured name",
	"1.2.840.113549.1.9.3":       "content type",
	"1.2.840.113549.1.9.4":       "message digest",
	"1.2.840.113549.1.9.5":       "signing time",
	"1.2.840.113549.1.9.7":       "challenge password",
	"1.2.840.113549.1.9.8":       "unstructured address",
	"1.2.840.113549.1.9.13":      "signing description",
	"1.2.840.113549.1.9.14":      "extension request",
	"1.2.840.113549.1.9.15":      "S/MIME capabilities",
	"1.2.840.113549.1.9.16":      "S/MIME object identifier registry",
	"1.2.840.113549.1.9.20":      "friendly name",
	"1.2.840.113549.1.9.22":      "cert types",
	"2.5.4.0":                    "object class",
	"2.5.4.1":                    "aliased entry",
	"2.5.4.2":                    "knowldgeinformation",
	"2.5.4.3":                    "common name",
	"2.5.4.4":                    "surname",
	"2.5.4.5":                    "serial number",
	"2.5.4.6":                    "country",
	"2.5.4.7":                    "locality",
	"2.5.4.8":                    "state or province",
	"2.5.4.9":                    "street address",
	"2.5.4.10":                   "organization",
	"2.5.4.11":                   "organizational unit",
	"2.5.4.12":                   "title",
	"2.5.4.13":                   "description",
	"2.5.4.14":                   "search guide",
	"2.5.4.15":                   "business category",
	"2.5.4.16":                   "postal address",
	"2.5.4.17":                   "postal code",
	"2.5.4.18":                   "post office box",
	"2.5.4.19":                   "physical delivery office name",
	"2.5.4.20":                   "telephone number",
	"2.5.4.21":                   "telex number",
	"2.5.4.22":                   "teletex terminal identifier",
	"2.5.4.23":                   "facsimile telephone number",
	"2.5.4.24":                   "x121 address",
	"2.5.4.25":                   "international ISDN number",
	"2.5.4.26":                   "registered address",
	"2.5.4.27":                   "destination indicator",
	"2.5.4.28":                   "preferred delivery method",
	"2.5.4.29":                   "presentation address",
	"2.5.4.30":                   "supported application context",
	"2.5.4.31":                   "member",
	"2.5.4.32":                   "owner",
	"2.5.4.33":                   "role occupant",
	"2.5.4.34":                   "see also",
	"2.5.4.35":                   "user password",
	"2.5.4.36":                   "user certificate",
	"2.5.4.37":                   "CA certificate",
	"2.5.4.38":                   "authority revocation list",
	"2.5.4.39":                   "certificate revocation list",
	"2.5.4.40":                   "cross certificate pair",
	"2.5.4.41":                   "name",
	"2.5.4.42":                   "given name",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generation qualifier",
	"2.5.4.45":                   "unique identifier",
	"2.5.4.46":                   "DN qualifier",
	"2.5.4.47":                   "enhanced search guide",
	"2.5.4.48":                   "protocol information",
	"2.5.4.49":                   "distinguished name",
	"2.5.4.50":                   "unique member",
	"2.5.4.51":                   "house identifier",
	"2.5.4.52":                   "supported algorithms",
	"2.5.4.53":                   "delta revocation list",
	"2.5.4.58":                   "attribute certificate",
	"2.5.4.65":                   "pseudonym",
}

func attributeName(oid asn1.ObjectIdentifier) string {
	var name = oid.String()
	if value, ok := attributeNameMap[name]; ok {
		return value
	}
	return name
}

// DumpHex dumps a byte sequence in hexdump(1) style to the terminal.
func DumpHex(d []byte, pad int) {
	var pads = strings.Repeat("  ", pad)
	for i := 0; i < len(d); i += 8 {
		var p = []byte{}
		for j := i; j < (i+8) && j < len(d); j++ {
			if strconv.IsPrint(rune(d[j])) {
				p = append(p, d[j])
			} else {
				p = append(p, '.')
			}
		}
		for j := len(p); j < 8; j++ {
			p = append(p, ' ')
		}
		w := (i + 8)
		if w > len(d) {
			w = len(d)
		}
		//h := hex.EncodeToString(d[i:w]) + strings.Repeat("  ", (i+8)-w)
		h := fmt.Sprintf("% x", d[i:w]) + strings.Repeat("   ", (i+8)-w)
		fmt.Printf("%s%#04x %s |%-8s|\n", pads, i, h, p)
	}
}

// DumpOID dumps the decoded OID to the terminal if available, else it will
// show the OID in dotted notation.
func DumpOID(oid asn1.ObjectIdentifier, pad int) {
	fmt.Print(strings.Repeat("  ", pad))
	switch {
	// RFC 5280, 4.2.1.12. Extended Key Usage
	case oid.Equal(oidExtKeyUsageAny):
		fmt.Printf("any (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageServerAuth):
		fmt.Printf("server authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageClientAuth):
		fmt.Printf("client authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageCodeSigning):
		fmt.Printf("code signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageEmailProtection):
		fmt.Printf("email protection (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECEndSystem):
		fmt.Printf("IPSEC end system (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECTunnel):
		fmt.Printf("IPSEC tunnel (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECUser):
		fmt.Printf("IPSEC user (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageTimeStamping):
		fmt.Printf("time stamping (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageOCSPSigning):
		fmt.Printf("OCSP signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageMicrosoftServerGatedCrypto):
		fmt.Printf("Microsoft server gated crypto (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageNetscapeServerGatedCrypto):
		fmt.Printf("Netscape server gated crypto (%s)\n", oid)
	// RFC 5280 4.2.1.4. Certificate Policies
	// - https://cabforum.org/object-registry/
	case oid.Equal([]int{2, 23, 140, 1, 1}):
		fmt.Printf("extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2}):
		fmt.Printf("baseline requirements (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 1}):
		fmt.Printf("CABF domain validated (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 2}):
		fmt.Printf("CABF subject identity validated (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 1, 1}):
		fmt.Printf("Digicert organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 2, 1}):
		fmt.Printf("Digicert extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 200, 1}):
		fmt.Printf("D-Trust organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 202, 1}):
		fmt.Printf("D-Trust extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 1}):
		fmt.Printf("GoDaddy domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 2}):
		fmt.Printf("GoDaddy organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 3}):
		fmt.Printf("GoDaddy extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113839, 0, 6, 3}):
		fmt.Printf("Identrust commercial domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 101, 3, 2, 1, 1, 5}):
		fmt.Printf("Identrust public sector domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 14777, 1, 2, 1}):
		fmt.Printf("Izenpe domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 528, 1, 1003, 1, 2, 5, 6}):
		fmt.Printf("Logius organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 1}):
		fmt.Printf("QuoVadis organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2}):
		fmt.Printf("QuoVadis extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 1}):
		fmt.Printf("Starfield domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 2}):
		fmt.Printf("Starfield organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 3}):
		fmt.Printf("Starfield extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 756, 1, 89, 1, 2, 1, 1}):
		fmt.Printf("SwissSign extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 54}):
		fmt.Printf("Symantec extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 34697, 1, 1}):
		fmt.Printf("Trend validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 5237, 1, 1, 3}):
		fmt.Printf("Trustis validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 30360, 3, 3, 3, 3, 4, 4, 3, 0}):
		fmt.Printf("Trustwave validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 2}):
		fmt.Printf("TurkTrust organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 5}):
		fmt.Printf("TurkTrust extended validation (%s)\n", oid)
	// - https://www.globalsign.com/repository/GlobalSign_CA_CP_v3.1.pdf
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 1}):
		fmt.Printf("GlobalSign extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 10}):
		fmt.Printf("GlobalSign domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 20}):
		fmt.Printf("GlobalSign organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 30}):
		fmt.Printf("GlobalSign time stamping (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 40}):
		fmt.Printf("GlobalSign client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 50}):
		fmt.Printf("GlobalSign code signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 60}):
		fmt.Printf("GlobalSign root signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 70}):
		fmt.Printf("GlobalSign trusted root certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 80}):
		fmt.Printf("GlobalSign retail industry EDI client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 81}):
		fmt.Printf("GlobalSign retail industry EDI server certificate (%s)\n", oid)
	// - http://www.entrust.net/CPS/pdf/webcps090809.pdf
	case oid.Equal([]int{1, 2, 840, 113533, 7, 75, 2}):
		fmt.Printf("Entrust SSL certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 3}):
		fmt.Printf("Entrust code signing certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 4}):
		fmt.Printf("Entrust client certificate (%s)\n", oid)
	// - http://www.symantec.com/content/en/us/about/media/repository/nf-ssp-pki-cps.pdf
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 1}):
		fmt.Printf("Symantec Trust Network class 1 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 2}):
		fmt.Printf("Symantec Trust Network class 2 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 3}):
		fmt.Printf("Symantec Trust Network class 3 (%s)\n", oid)
	default:
		attr := oid.String()
		if value, ok := attributeNameMap[attr]; ok {
			fmt.Printf("%s (%s)\n", value, attr)
		} else {
			fmt.Printf("Unknown (%s)\n", oid)
		}
	}
}

// DumpX509Extension dumps an X.509 certificate extension to the terminal.
func DumpX509Extension(ext pkix.Extension, pad int) {
	var pads = strings.Repeat("  ", pad)
	var crit = "critical"
	if !ext.Critical {
		crit = ""
	}

	switch {
	case ext.Id.Equal(oidMicrosoftCertSrv):
		// http://msdn.microsoft.com/en-us/library/windows/desktop/aa376550(v=vs.85).aspx
		fmt.Printf("%sMicrosoft certificate server:\n", pads)
		var version int
		_, err := asn1.Unmarshal(ext.Value, &version)
		if err == nil {
			ci := version & 0xff
			ki := version >> 16
			fmt.Printf("%s  Certificate index: %d\n", pads, ci)
			fmt.Printf("%s  Key index: %d\n", pads, ki)
		}

	case ext.Id.Equal(oidMicrosoftPreviousCertHash):
		fmt.Printf("%sMicrosoft previous CA certificate hash:\n", pads)
		var hash asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &hash)
		if err == nil {
			DumpData(hash.Bytes, pad+1)
		}

	case ext.Id.Equal(oidMicrosoftCertificateTemplate):
		// http://msdn.microsoft.com/en-us/library/cc250012.aspx
		fmt.Printf("%sMicrosoft certificate template (v2):\n", pads)
		var template struct {
			ID         asn1.ObjectIdentifier
			MajVersion int64 `asn1:"optional"`
			MinVersion int64 `asn1:"optional"`
		}
		_, err := asn1.Unmarshal(ext.Value, &template)
		if err == nil {
			fmt.Printf("%s  ID: %s\n", pads, template.ID)
			if template.MinVersion > 0 {
				fmt.Printf("%s  minor version: %d\n", pads, template.MinVersion)
			}
			if template.MajVersion > 0 {
				fmt.Printf("%s  major version: %d\n", pads, template.MajVersion)
			}
		}

	case ext.Id.Equal(oidExtensionAuthorityKeyID):
		fmt.Printf("%sX509v3 Authority key identifier: %s\n", pads, crit)
		aki := &AuthorityKeyID{}
		_, err := asn1.Unmarshal(ext.Value, aki)
		if err == nil {
			s := fmt.Sprintf("keyid:֬%s", certutil.GetHexFormatted(aki.ID, ":"))
			DumpData(s, pad+1)
		}

	case ext.Id.Equal(oidExtBasicConstraints):
		fmt.Printf("%sX509v3 Basic Constraints: %s\n", pads, crit)
		var b struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}
		_, err := asn1.Unmarshal(ext.Value, &b)
		if err == nil {
			s := fmt.Sprintf("CA:֬%v", b.IsCA)
			s = strings.ToUpper(s)
			DumpData(s, pad+1)
		}

	case ext.Id.Equal(oidExtensionKeyUsage):
		// RFC 5280, 4.2.1.3
		fmt.Printf("%sKey usage: %s\n", pads, crit)
		var usageBits asn1.BitString
		_, err := asn1.Unmarshal(ext.Value, &usageBits)
		if err == nil {
			for i := 0; i < len(keyUsages); i++ {
				if usageBits.At(i) != 0 {
					fmt.Printf("%s  %s (%d)\n", pads, keyUsages[i], i)
				}
			}
		}

	case ext.Id.Equal(oidExtensionSubjectKeyID):
		fmt.Printf("%sSubject key identifier: %s\n", pads, crit)
		var keyid []byte
		_, err := asn1.Unmarshal(ext.Value, &keyid)
		if err == nil {
			DumpData(keyid, pad+1)
		}

	case ext.Id.Equal(oidExtensionExtendedKeyUsage):
		// RFC 5280, 4.2.1.12.  Extended Key Usage
		fmt.Printf("%sExtended key usage: %s\n", pads, crit)
		var extKeyUsage []asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
		if err == nil {
			for _, oid := range extKeyUsage {
				DumpOID(oid, pad+1)
			}
		}

	case ext.Id.Equal(oidExtensionNSCertificateComment):
		fmt.Printf("%sNetscape certificate comment:\n", pads)
		var comment string
		_, err := asn1.Unmarshal(ext.Value, &comment)
		if err == nil {
			fmt.Printf("%s  %s\n", pads, comment)
		}

	case ext.Id.Equal(oidExtensionLogotype):
		// Logotype is quite complex, and contains mostly images, we'll skip parsing it for now and
		// only print the name of the extension type.
		fmt.Printf("%sLogo type: %s\n", pads, crit)
		DumpHex(ext.Value, pad+1)

	default:
		DumpOID(ext.Id, pad)
		DumpHex(ext.Value, pad+1)

	}
}

func format(s, sep, fill string) string {
	if len(s)%2 > 0 {
		s = fill + s
	}
	var p = []string{}
	for j := 0; j < len(s); j += 2 {
		p = append(p, s[j:j+2])
	}
	return strings.Join(p, sep)
}

// DumpData dumps any structure as colon padded data to the terminal, mainly
// used to dump (long) integers or byte slices.
func DumpData(i interface{}, pad int) {
	var pads = strings.Repeat("  ", pad)
	var x = 80 - pad

	switch v := i.(type) {
	case *big.Int:
		var p = format(fmt.Sprintf("%x", v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	case string:
		for j := 0; j < len(v); j += x {
			m := j + x
			if m > len(v) {
				m = len(v)
			}
			fmt.Printf("%s%s\n", pads, v[j:m])
		}

	case *string:
		DumpData(*v, pad)

	case []uint8: // aka []byte
		var p = format(hex.EncodeToString(v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	default:
		panic(fmt.Sprintf("don't know how to dump %T", v))
	}
}

func uintToHex16(i uint) string {
	return fmt.Sprintf("%#0*x", places(i, 4, 4, 16), i)
}

// places is used to see how many digits we need to
// print for integers (including some minimum number
// which is determined by the base), given how many
// bits are valid.
func places(i uint, group, min, max int) int {
	n := bits.Len(i)

	r := n / group

	if n%group != 0 {
		r++
	}

	if r < min {
		return min
	}

	if r > max {
		return max
	}

	return r
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ParseCertificateFile parses x509 certificate file.
func ParseCertificateFile(certFile string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return ParseCertificatePEM(certPEM)
}

// ParseCertificatePEM parses an x509 certificate PEM.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ParsePublicKeyPEM is used to parse RSA and ECDSA public keys from PEMs
func ParsePublicKeyPEM(data []byte) (interface{}, error) {
	block, data := pem.Decode(data)
	if block != nil {
		var rawKey interface{}
		var err error
		if rawKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				rawKey = cert.PublicKey
			} else {
				return nil, err
			}
		}

		if rsaPublicKey, ok := rawKey.(*rsa.PublicKey); ok {
			return rsaPublicKey, nil
		}
		if ecPublicKey, ok := rawKey.(*ecdsa.PublicKey); ok {
			return ecPublicKey, nil
		}
		if edPublicKey, ok := rawKey.(ed25519.PublicKey); ok {
			return edPublicKey, nil
		}
	}

	return nil, errors.New("data does not contain any valid public keys")
}

// SplitSubN uses type assertion to get the modulus from a public or private key
func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

// DumpPublicKey dumps a public key to the terminal.
func DumpPublicKey(v interface{}, pad int) {
	switch pub := v.(type) {
	case *ecdsa.PublicKey:
		DumpPublicKeyEcdsa(pub, pad)
	case *rsa.PublicKey:
		DumpPublicKeyRsa(pub, pad)
	case *dsa.PublicKey:
		DumpPublicKeyDsa(pub, pad)
	default:
		var pads = strings.Repeat("  ", pad)
		fmt.Printf("%sunsupported (%T)\n", pads, pub)
	}
}

// DumpPublicKeyDsa dumps a DSA public key to the terminal.
func DumpPublicKeyDsa(key *dsa.PublicKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sPublic-Key: (%v bits)\n", pads, key.P.BitLen())
	fmt.Printf("%s  pub:\n", pads)
	DumpData(key.Y, pad+2)
	fmt.Printf("%s  P:\n", pads)
	DumpData(key.P, pad+2)
	fmt.Printf("%s  Q:\n", pads)
	DumpData(key.Q, pad+2)
	fmt.Printf("%s  G:\n", pads)
	DumpData(key.G, pad+2)
}

// DumpPublicKeyEcdsa dumps a ECDSA public key to the terminal.
func DumpPublicKeyEcdsa(key *ecdsa.PublicKey, pad int) {
	curveString := ""
	switch key.Curve {
	case elliptic.P256():
		curveString = "prime256v1"
	case elliptic.P384():
		curveString = "secp384r1"
	case elliptic.P521():
		curveString = "secp521r1"
	default:
		curveString = "ECDSA (unknown curve)"
	}
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sPublic Key (%d bits):\n", pads, key.Params().BitSize)
	DumpData("pub:", 8)
	pub := elliptic.Marshal(key.Curve, key.X, key.Y)
	DumpData(pub, pad+2)
	DumpData(fmt.Sprintf("ASN1 OID: %s", curveString), 8)
	DumpData(fmt.Sprintf("NIST Curve: %s", key.Params().Name), 8)
}

// DumpPublicKeyRsa dumps a RSA public key to the terminal.
func DumpPublicKeyRsa(key *rsa.PublicKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sPublic-Key: (%d bit):\n", pads, key.N.BitLen())
	fmt.Printf("%sModulus:\n", pads)
	DumpData(key.N, pad+2)
	fmt.Printf("%sExponent: %d (%#x)\n", pads, key.E, key.E)
}

func main() {
	app := &cli.App{
		Name:  "pkipeek",
		Usage: "Read PKI files",
		Action: func(c *cli.Context) error {
			filePath := c.Args().Get(0)
			if filePath == "" {
				return fmt.Errorf("No path given")
			}
			if fileExists(filePath) {
				cert, err := ParseCertificateFile(filePath)
				if err != nil {
					return err
				}

				DumpData("Certificate:", 0)
				DumpData("Data:", 2)
				DumpData(fmt.Sprintf("Version: %v", cert.Version), 4)
				uintSerial, err := strconv.ParseUint(cert.SerialNumber.String(), 10, 64)
				if err != nil {
					return err
				}
				DumpData(fmt.Sprintf("Serial Number: %s (%v)", cert.SerialNumber, uintToHex16(uint(uintSerial))), 4)
				DumpData(fmt.Sprintf("Signature Algorithm: %s", cert.SignatureAlgorithm), 2)
				DumpData(fmt.Sprintf("Issuer: %s", cert.Issuer), 2)
				DumpData("Validity:", 4)
				DumpData(fmt.Sprintf("Not Before: %s", cert.NotBefore), 6)
				DumpData(fmt.Sprintf("Not After: %s", cert.NotAfter), 6)
				DumpData(fmt.Sprintf("Subject: %s", cert.Subject), 4)
				DumpData("Subject Public Key Info:", 4)
				DumpData(fmt.Sprintf("Public Key Algorithm: %s", cert.PublicKeyAlgorithm), 6)

				switch cert.PublicKey.(type) {
				case *rsa.PublicKey:
					DumpPublicKey(cert.PublicKey, 8)
					if len(cert.Extensions) > 0 {
						DumpData("X509v3 extensions:", 6)
						for _, ext := range cert.Extensions {
							DumpX509Extension(ext, 8)
						}
					}
					if len(cert.ExtraExtensions) > 0 {
						for _, ext := range cert.ExtraExtensions {
							DumpX509Extension(ext, 8)
						}
					}
					DumpData(fmt.Sprintf("Signature Algorithm: %s", cert.SignatureAlgorithm), 4)
					DumpData(cert.Signature, 6)
					rawPEM := string(helpers.EncodeCertificatePEM(cert))
					fmt.Printf(rawPEM)
				case *ecdsa.PublicKey:
					DumpPublicKey(cert.PublicKey, 8)
					if len(cert.Extensions) > 0 {
						DumpData("X509v3 extensions:", 6)
						for _, ext := range cert.Extensions {
							DumpX509Extension(ext, 8)
						}
					}
					if len(cert.ExtraExtensions) > 0 {
						for _, ext := range cert.ExtraExtensions {
							DumpX509Extension(ext, 8)
						}
					}
					DumpData(fmt.Sprintf("Signature Algorithm: %s", cert.SignatureAlgorithm), 4)
					DumpData(cert.Signature, 6)
					rawPEM := string(helpers.EncodeCertificatePEM(cert))
					fmt.Printf(rawPEM)
				case *dsa.PublicKey:
					DumpPublicKey(cert.PublicKey, 8)
					if len(cert.Extensions) > 0 {
						DumpData("X509v3 extensions:", 6)
						for _, ext := range cert.Extensions {
							DumpX509Extension(ext, 8)
						}
					}
					if len(cert.ExtraExtensions) > 0 {
						for _, ext := range cert.ExtraExtensions {
							DumpX509Extension(ext, 8)
						}
					}
					DumpData(fmt.Sprintf("Signature Algorithm: %s", cert.SignatureAlgorithm), 4)
					DumpData(cert.Signature, 6)
					rawPEM := string(helpers.EncodeCertificatePEM(cert))
					fmt.Printf(rawPEM)
				default:
					return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
				}

				return nil

			} else {
				return fmt.Errorf("File does not exist: %s", filePath)
			}
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}
}
