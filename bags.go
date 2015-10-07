package pkcs12encr

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

//see https://tools.ietf.org/html/rfc7292#appendix-D
var (
	oidKeyBagType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPkcs8ShroudedKeyBagType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBagType             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidCrlBagType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	oidSecretBagType           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidSafeContentsBagType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
)

var (
	oidCertTypeX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidLocalKeyIDAttribute     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func encodePkcs8ShroudedKeyBag(privateKey interface{}, password []byte, alg String) (bag safeBag, err error ) {
	data, err := asn1.Marshal(privateKey)
	if err != nil{
		return nil, err
	}


	pkinfo, err := pbEncrypt(data, password, alg)
	if err != nil{
		return nil, err
	}

	asn1Data = asn1.Marshal(pkinfo)
	if err != nil{
		return nil, err
	}	
	bag := new(safeBag)
	bag.Value.Bytes = asn1Data
	bag.ID = oidPkcs8ShroudedKeyBagType
	//bag.Attributes = ???
	return
}

func encodeCertBag(x509Certificates []byte) (bag safeBag, err error) {
	certBag := new(certBag)
	certBag.ID := oidCertTypeX509Certificate
	certBag.Data = x509Certificates

	asn1Data, err := asn1.Marshal(certBag)
	if err != nil {
		return nil, err
	}

	bag := new(safeBag)
	bag.ID = oidCertBagType
	bag.Value.Bytes = asn1Data
	//bag.Attributes = ???

	return 
}