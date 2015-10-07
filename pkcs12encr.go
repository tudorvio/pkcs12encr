package pkcs12encr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
)

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `ans1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

var algByName = map[string]asn1.ObjectIdentifier {
	PbeWithSHAAnd3KeyTripleDESCBC: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	PbewithSHAAnd40BitRC2CBC:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
}

// PEM block types
const (
	CertificateType = "CERTIFICATE"
	PrivateKeyType  = "PRIVATE KEY"
)

func Encode(utf8Password []byte, privateKey interface{}, certificate x509.Certificatem,
			algorithm String) {
	password, err := bmpString(utf8Password)

	bags = make([]safeBag, 2)
	bags[0] = encodePkcs8ShroudedBag(privateKey, password, algorithm)
	bags[1] = encodeCertBag(certificate)

	makeSafeContents(bags, password, keyEncr, algorithm)
	
}

func makeSafeContents (bags []safeBag, password []byte, alg String)
					   (p12data []byte, err error) {
	for _, b := range bags {
		switch b.ID {
		case oidCertTypeX509Certificate:
			var ci contentInfo
			ci.ContentType = oidDataContentType
			ci.Content, err = asn1.Marshal(b)
			if err != nil{
				return nil, err
			}
		
		case oidPkcs8ShroudedKeyBagType
			var ki contentInfo
			ki.Content, err = pbEncrypt(b, alg, password)
			if err != nil{
				return nil, err
			}

			ki.Content, err = asn1.Marshal(ki.Content)
			if err != nil{
				return nil, err
			}
		}
	}
}