// internal/sso/saml.go — SAML 2.0 Service Provider.

package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// SAMLProvider wraps a crewjam ServiceProvider for one tenant's IdP config.
type SAMLProvider struct {
	sp           saml.ServiceProvider
	emailAttr    string
	nameAttr     string
	roleAttr     string
}

// NewSAMLProvider constructs a ServiceProvider from stored config fields.
// baseURL is the TraceGuard backend public base URL, e.g. "https://soc.example.com".
func NewSAMLProvider(
	idpMetadataXML, spKeyPEM, spCertPEM string,
	baseURL, emailAttr, nameAttr, roleAttr string,
) (*SAMLProvider, error) {
	if emailAttr == "" {
		emailAttr = "email"
	}
	if nameAttr == "" {
		nameAttr = "name"
	}

	// Parse SP private key.
	keyBlock, _ := pem.Decode([]byte(spKeyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("saml: invalid SP key PEM")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SP key: %w", err)
	}

	// Parse SP certificate.
	certBlock, _ := pem.Decode([]byte(spCertPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("saml: invalid SP cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SP cert: %w", err)
	}

	// Parse IdP metadata.
	idpMeta := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(idpMetadataXML), idpMeta); err != nil {
		return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse base URL: %w", err)
	}

	metaURL := *base
	metaURL.Path = "/api/v1/sso/saml/metadata"

	acsURL := *base
	acsURL.Path = "/api/v1/sso/saml/acs"

	sp := saml.ServiceProvider{
		Key:         rsaKey,
		Certificate: cert,
		MetadataURL: metaURL,
		AcsURL:      acsURL,
		IDPMetadata: idpMeta,
	}

	return &SAMLProvider{
		sp:        sp,
		emailAttr: emailAttr,
		nameAttr:  nameAttr,
		roleAttr:  roleAttr,
	}, nil
}

// MetadataXML returns the SP metadata XML to give to the IdP administrator.
func (p *SAMLProvider) MetadataXML() ([]byte, error) {
	meta := p.sp.Metadata()
	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// InitiateLogin builds the IdP redirect URL.
// relayState is opaque data (e.g. tenantID) that the IdP echoes back in the ACS post.
func (p *SAMLProvider) InitiateLogin(relayState string) (redirectURL string, requestID string, err error) {
	req, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return "", "", fmt.Errorf("saml: make authn request: %w", err)
	}
	redirect, err := req.Redirect(relayState, &p.sp)
	if err != nil {
		return "", "", fmt.Errorf("saml: build redirect: %w", err)
	}
	return redirect.String(), req.ID, nil
}

// ParseAssertion validates the SAMLResponse in r and returns the Identity.
// possibleRequestIDs should include the request ID from InitiateLogin.
func (p *SAMLProvider) ParseAssertion(r *http.Request, possibleRequestIDs []string) (*Identity, error) {
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("saml: parse response: %w", err)
	}

	id := &Identity{
		Subject: assertion.Subject.NameID.Value,
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			vals := make([]string, len(attr.Values))
			for i, v := range attr.Values {
				vals[i] = v.Value
			}
			switch attr.Name {
			case p.emailAttr, "emailAddress", "urn:oid:0.9.2342.19200300.100.1.3":
				if len(vals) > 0 {
					id.Email = vals[0]
				}
			case p.nameAttr, "displayName", "urn:oid:2.16.840.1.113730.3.1.241":
				if len(vals) > 0 {
					id.Name = vals[0]
				}
			}
			if p.roleAttr != "" && attr.Name == p.roleAttr && len(vals) > 0 {
				id.Role = vals[0]
			}
		}
	}

	// Fall back to NameID as email if no email attribute mapped.
	if id.Email == "" {
		id.Email = assertion.Subject.NameID.Value
	}

	return id, nil
}

// GenerateSPKeyPair creates a new 2048-bit RSA key + self-signed cert for use as SP signing key.
// Returns (keyPEM, certPEM, error).
func GenerateSPKeyPair() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TraceGuard EDR"},
			CommonName:   "TraceGuard SAML SP",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
	return keyPEM, certPEM, nil
}

// DecodeBase64SAMLResponse decodes a base64-encoded SAML response for inspection.
// Useful in debug/test tooling only.
func DecodeBase64SAMLResponse(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
