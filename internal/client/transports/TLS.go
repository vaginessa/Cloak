package transports

import (
	"github.com/cbeuw/Cloak/internal/client/browsers"
	"github.com/cbeuw/Cloak/internal/common"
	log "github.com/sirupsen/logrus"
	"net"
)

type DirectTLS struct {
	*common.TLSConn
	Browser browsers.Browser
}

// Handshake handles the TLS handshake for a given conn and returns the sessionKey
// if the server proceed with Cloak authentication
func (tls *DirectTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	payload, sharedSecret := makeAuthenticationPayload(authInfo)

	// random is marshalled ephemeral pub key 32 bytes
	// The authentication ciphertext and its tag are then distributed among SessionId and X25519KeyShare
	fields := browsers.ClientHelloFields{
		Random:         payload.randPubKey[:],
		SessionId:      payload.ciphertextWithTag[0:32],
		X25519KeyShare: payload.ciphertextWithTag[32:64],
		ServerName:     authInfo.MockDomain,
	}
	chOnly := tls.Browser.ComposeClientHello(fields)
	chWithRecordLayer := common.AddRecordLayer(chOnly, common.Handshake, common.VersionTLS11)
	_, err = rawConn.Write(chWithRecordLayer)
	if err != nil {
		return
	}
	log.Trace("client hello sent successfully")
	tls.TLSConn = common.NewTLSConn(rawConn)

	buf := make([]byte, 1024)
	log.Trace("waiting for ServerHello")
	_, err = tls.Read(buf)
	if err != nil {
		return
	}

	encrypted := append(buf[6:38], buf[84:116]...)
	nonce := encrypted[0:12]
	ciphertextWithTag := encrypted[12:60]
	sessionKeySlice, err := common.AESGCMDecrypt(nonce, sharedSecret[:], ciphertextWithTag)
	if err != nil {
		return
	}
	copy(sessionKey[:], sessionKeySlice)

	for i := 0; i < 2; i++ {
		// ChangeCipherSpec and EncryptedCert (in the format of application data)
		_, err = tls.Read(buf)
		if err != nil {
			return
		}
	}
	return sessionKey, nil

}
