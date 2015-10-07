package pkcs12encr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/Azure/go-pkcs12/rc2"
)

const (
	pbeWithSHAAnd3KeyTripleDESCBC = "pbeWithSHAAnd3-KeyTripleDES-CBC"
	pbewithSHAAnd40BitRC2CBC      = "pbewithSHAAnd40BitRC2-CBC"
)

var (
	oidPbeWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPbewithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

var algByOID = map[string]string{
	oidPbeWithSHAAnd3KeyTripleDESCBC.String(): pbeWithSHAAnd3KeyTripleDESCBC,
	oidPbewithSHAAnd40BitRC2CBC.String():      pbewithSHAAnd40BitRC2CBC,
}

var blockcodeByAlg = map[string]func(key []byte) (cipher.Block, error){
	pbeWithSHAAnd3KeyTripleDESCBC: des.NewTripleDESCipher,
	pbewithSHAAnd40BitRC2CBC: func(key []byte) (cipher.Block, error) {
		return rc2.New(key, len(key)*8)
	},
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

type decryptable interface {
	GetAlgorithm() pkix.AlgorithmIdentifier
	GetData() []byte
}

const (
	saltSize = 16
	itCount = 100000
)

func generateSalt(password []byte) []byte {
    buff := make([]byte, saltSize, saltSize+sha1.Size)
    _, err := io.ReadFull(rand.Reader, buf)

    if err != nil {
            fmt.Printf("Random read failed: %v", err)
            os.Exit(1)
        }

    hash := sha1.New()
    hash.Write(buf)
    hash.Write(passord)
    return hash.Sum(buf)
}

func pbEncrypterFor(algorithm String, password []byte) (cbc cipher.BlockMode, params pbeParams,  err error){
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. Should I implement this?
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2

	var params pbeParams

	params.Salt = generateSalt(password)
	params.Iterations = itCount

	k := deriveKeyByAlg[algorithmName](params.Salt, params.Iterations)
	iv := deriveIVByAlg[algorithmName](params.Salt, params.Iterations)

	code, err := blockcodeByAlg[algorithmName](k)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(code, iv)
	return cbc, params, nil
}

func pbEnrypt(info []byte, algorithm String, password []byte) (encr encryptedContentInfo, err error){
	cbc, params, err := pbEncrypterFor(algorithm, password)
	if err != nil {
		return nil, err
	}

	encrypted = make([]byte, len(info))
	cbc.CryptBlocks(encrypted, info)

	params, err := asn1.Marshal(params)
	if err != nil {
		return nil, err
	}

	algorithm.Parameters.FullBytes = params
	
	encr = new(encryptedContentInfo)
	encr.Algorithm = algorithm
	encr.EncryptedContent = encrypted
	// Content type could be added in the pkcs12, need to see later.
	encr.ContentType = oidEncryptedDataContentType
	return
}
	