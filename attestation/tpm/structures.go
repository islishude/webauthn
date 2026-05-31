package tpm

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

const (
	tpmGeneratedValue  = 0xff544347
	tpmSTAttestCertify = 0x8017

	tpmAlgRSA    = 0x0001
	tpmAlgSHA256 = 0x000b
	tpmAlgSHA384 = 0x000c
	tpmAlgSHA512 = 0x000d
	tpmAlgNull   = 0x0010
	tpmAlgRSASSA = 0x0014
	tpmAlgRSAPSS = 0x0016
	tpmAlgECDSA  = 0x0018
	tpmAlgECC    = 0x0023

	tpmECCNISTP256 = 0x0003
	tpmECCNISTP384 = 0x0004
	tpmECCNISTP521 = 0x0005
)

var errTPMTruncated = errors.New("truncated tpm structure")

type coseAlgorithmSpec struct {
	cose         protocol.COSEAlgorithmIdentifier
	signatureAlg uint16
	hashAlg      uint16
}

func signatureAlgorithmSpec(algorithm protocol.COSEAlgorithmIdentifier) (coseAlgorithmSpec, bool) {
	switch algorithm {
	case -7:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgECDSA, hashAlg: tpmAlgSHA256}, true
	case -35:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgECDSA, hashAlg: tpmAlgSHA384}, true
	case -36:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgECDSA, hashAlg: tpmAlgSHA512}, true
	case -257:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSASSA, hashAlg: tpmAlgSHA256}, true
	case -258:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSASSA, hashAlg: tpmAlgSHA384}, true
	case -259:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSASSA, hashAlg: tpmAlgSHA512}, true
	case -37:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSAPSS, hashAlg: tpmAlgSHA256}, true
	case -38:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSAPSS, hashAlg: tpmAlgSHA384}, true
	case -39:
		return coseAlgorithmSpec{cose: algorithm, signatureAlg: tpmAlgRSAPSS, hashAlg: tpmAlgSHA512}, true
	default:
		return coseAlgorithmSpec{}, false
	}
}

type publicArea struct {
	raw     []byte
	keyType uint16
	nameAlg uint16
	ec2     *publicAreaEC2
	rsa     *publicAreaRSA
}

type publicAreaEC2 struct {
	curve string
	x     []byte
	y     []byte
}

type publicAreaRSA struct {
	modulus  []byte
	exponent uint32
}

func parsePublicArea(raw []byte) (publicArea, error) {
	reader := newTPMReader(raw)
	keyType, err := reader.uint16()
	if err != nil {
		return publicArea{}, publicAreaError(err)
	}
	nameAlg, err := reader.uint16()
	if err != nil {
		return publicArea{}, publicAreaError(err)
	}
	if _, err := reader.uint32(); err != nil {
		return publicArea{}, publicAreaError(err)
	}
	if _, err := reader.sizedBytes(); err != nil {
		return publicArea{}, publicAreaError(err)
	}

	parsed := publicArea{
		raw:     append([]byte{}, raw...),
		keyType: keyType,
		nameAlg: nameAlg,
	}
	switch keyType {
	case tpmAlgECC:
		ec2, err := parseECCPublicArea(reader)
		if err != nil {
			return publicArea{}, err
		}
		parsed.ec2 = &ec2
	case tpmAlgRSA:
		rsa, err := parseRSAPublicArea(reader)
		if err != nil {
			return publicArea{}, err
		}
		parsed.rsa = &rsa
	default:
		return publicArea{}, ErrUnsupportedKey
	}
	if reader.remaining() != 0 {
		return publicArea{}, ErrInvalidPublicArea
	}

	return parsed, nil
}

func parseECCPublicArea(reader *tpmReader) (publicAreaEC2, error) {
	if err := parseSymmetricDefinition(reader); err != nil {
		return publicAreaEC2{}, err
	}
	if err := parseScheme(reader); err != nil {
		return publicAreaEC2{}, err
	}
	curveID, err := reader.uint16()
	if err != nil {
		return publicAreaEC2{}, publicAreaError(err)
	}
	if err := parseScheme(reader); err != nil {
		return publicAreaEC2{}, err
	}
	x, err := reader.sizedBytes()
	if err != nil {
		return publicAreaEC2{}, publicAreaError(err)
	}
	y, err := reader.sizedBytes()
	if err != nil {
		return publicAreaEC2{}, publicAreaError(err)
	}
	curve, coordinateLength, ok := tpmCurve(curveID)
	if !ok || len(x) != coordinateLength || len(y) != coordinateLength {
		return publicAreaEC2{}, ErrUnsupportedKey
	}

	return publicAreaEC2{curve: curve, x: x, y: y}, nil
}

func parseRSAPublicArea(reader *tpmReader) (publicAreaRSA, error) {
	if err := parseSymmetricDefinition(reader); err != nil {
		return publicAreaRSA{}, err
	}
	if err := parseScheme(reader); err != nil {
		return publicAreaRSA{}, err
	}
	if _, err := reader.uint16(); err != nil {
		return publicAreaRSA{}, publicAreaError(err)
	}
	exponent, err := reader.uint32()
	if err != nil {
		return publicAreaRSA{}, publicAreaError(err)
	}
	if exponent == 0 {
		exponent = 65537
	}
	modulus, err := reader.sizedBytes()
	if err != nil {
		return publicAreaRSA{}, publicAreaError(err)
	}
	if len(modulus) == 0 {
		return publicAreaRSA{}, ErrUnsupportedKey
	}

	return publicAreaRSA{modulus: modulus, exponent: exponent}, nil
}

func parseSymmetricDefinition(reader *tpmReader) error {
	algorithm, err := reader.uint16()
	if err != nil {
		return publicAreaError(err)
	}
	if algorithm != tpmAlgNull {
		return ErrUnsupportedKey
	}

	return nil
}

func parseScheme(reader *tpmReader) error {
	scheme, err := reader.uint16()
	if err != nil {
		return publicAreaError(err)
	}
	if scheme == tpmAlgNull {
		return nil
	}
	if _, err := reader.uint16(); err != nil {
		return publicAreaError(err)
	}

	return nil
}

func tpmCurve(curveID uint16) (string, int, bool) {
	switch curveID {
	case tpmECCNISTP256:
		return codec.EC2CurveP256, 32, true
	case tpmECCNISTP384:
		return codec.EC2CurveP384, 48, true
	case tpmECCNISTP521:
		return codec.EC2CurveP521, 66, true
	default:
		return "", 0, false
	}
}

func validatePublicAreaBinding(parsed publicArea, material codec.CredentialPublicKeyMaterial) error {
	switch parsed.keyType {
	case tpmAlgECC:
		if parsed.ec2 == nil || material.EC2 == nil {
			return ErrUnsupportedKey
		}
		if parsed.ec2.curve != material.EC2.Curve ||
			!bytes.Equal(parsed.ec2.x, material.EC2.X) ||
			!bytes.Equal(parsed.ec2.y, material.EC2.Y) {
			return ErrPublicKeyMismatch
		}
	case tpmAlgRSA:
		if parsed.rsa == nil || material.RSA == nil {
			return ErrUnsupportedKey
		}
		if parsed.rsa.exponent != material.RSA.Exponent || !bytes.Equal(parsed.rsa.modulus, material.RSA.Modulus) {
			return ErrPublicKeyMismatch
		}
	default:
		return ErrUnsupportedKey
	}

	return nil
}

func (p publicArea) name() ([]byte, error) {
	digest, err := tpmHash(p.nameAlg, p.raw)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 2, 2+len(digest))
	binary.BigEndian.PutUint16(out, p.nameAlg)
	out = append(out, digest...)

	return out, nil
}

type certifyInfo struct {
	extraData []byte
	name      []byte
}

func parseCertInfo(raw []byte) (certifyInfo, error) {
	reader := newTPMReader(raw)
	magic, err := reader.uint32()
	if err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if magic != tpmGeneratedValue {
		return certifyInfo{}, ErrInvalidCertInfo
	}
	attestType, err := reader.uint16()
	if err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if attestType != tpmSTAttestCertify {
		return certifyInfo{}, ErrInvalidCertInfo
	}
	if _, err := reader.sizedBytes(); err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	extraData, err := reader.sizedBytes()
	if err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if err := reader.skip(17); err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if _, err := reader.uint64(); err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	name, err := reader.sizedBytes()
	if err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if _, err := reader.sizedBytes(); err != nil {
		return certifyInfo{}, certInfoError(err)
	}
	if reader.remaining() != 0 {
		return certifyInfo{}, ErrInvalidCertInfo
	}

	return certifyInfo{extraData: extraData, name: name}, nil
}

func validateCertInfoBinding(parsed certifyInfo, expectedExtraData []byte, expectedName []byte) error {
	if !bytes.Equal(parsed.extraData, expectedExtraData) || !bytes.Equal(parsed.name, expectedName) {
		return ErrInvalidCertInfo
	}

	return nil
}

type tpmSignature struct {
	signature []byte
}

func parseTPMSignature(raw []byte, spec coseAlgorithmSpec) (tpmSignature, error) {
	reader := newTPMReader(raw)
	signatureAlg, err := reader.uint16()
	if err != nil {
		return tpmSignature{}, signatureError(err)
	}
	if signatureAlg != spec.signatureAlg {
		return tpmSignature{}, ErrInvalidSignature
	}
	hashAlg, err := reader.uint16()
	if err != nil {
		return tpmSignature{}, signatureError(err)
	}
	if hashAlg != spec.hashAlg {
		return tpmSignature{}, ErrInvalidSignature
	}

	var signature []byte
	switch signatureAlg {
	case tpmAlgECDSA:
		signature, err = parseECDSASignature(reader)
	case tpmAlgRSASSA, tpmAlgRSAPSS:
		signature, err = reader.sizedBytes()
	default:
		return tpmSignature{}, ErrInvalidSignature
	}
	if err != nil {
		return tpmSignature{}, signatureError(err)
	}
	if len(signature) == 0 || reader.remaining() != 0 {
		return tpmSignature{}, ErrInvalidSignature
	}

	return tpmSignature{signature: signature}, nil
}

func parseECDSASignature(reader *tpmReader) ([]byte, error) {
	rBytes, err := reader.sizedBytes()
	if err != nil {
		return nil, err
	}
	sBytes, err := reader.sizedBytes()
	if err != nil {
		return nil, err
	}
	if len(rBytes) == 0 || len(sBytes) == 0 {
		return nil, ErrInvalidSignature
	}

	der, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		R: new(big.Int).SetBytes(rBytes),
		S: new(big.Int).SetBytes(sBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return der, nil
}

func signedData(authenticatorData []byte, clientDataHash []byte) []byte {
	out := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	out = append(out, authenticatorData...)
	out = append(out, clientDataHash...)

	return out
}

func tpmHash(algorithm uint16, data []byte) ([]byte, error) {
	switch algorithm {
	case tpmAlgSHA256:
		digest := sha256.Sum256(data)
		return digest[:], nil
	case tpmAlgSHA384:
		digest := sha512.Sum384(data)
		return digest[:], nil
	case tpmAlgSHA512:
		digest := sha512.Sum512(data)
		return digest[:], nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func publicAreaError(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidPublicArea, err)
}

func certInfoError(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidCertInfo, err)
}

func signatureError(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
}

type tpmReader struct {
	data []byte
	pos  int
}

func newTPMReader(data []byte) *tpmReader {
	return &tpmReader{data: data}
}

func (r *tpmReader) uint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errTPMTruncated
	}
	out := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2

	return out, nil
}

func (r *tpmReader) uint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errTPMTruncated
	}
	out := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4

	return out, nil
}

func (r *tpmReader) uint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, errTPMTruncated
	}
	out := binary.BigEndian.Uint64(r.data[r.pos : r.pos+8])
	r.pos += 8

	return out, nil
}

func (r *tpmReader) sizedBytes() ([]byte, error) {
	size, err := r.uint16()
	if err != nil {
		return nil, err
	}
	if int(size) > r.remaining() {
		return nil, errTPMTruncated
	}
	out := append([]byte{}, r.data[r.pos:r.pos+int(size)]...)
	r.pos += int(size)

	return out, nil
}

func (r *tpmReader) skip(count int) error {
	if count < 0 || count > r.remaining() {
		return errTPMTruncated
	}
	r.pos += count

	return nil
}

func (r *tpmReader) remaining() int {
	return len(r.data) - r.pos
}
