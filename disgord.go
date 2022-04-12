package disgord

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	v9URL = "https://discord.com/api/v9"
	meURL = v9URL + "/users/@me"
)

type discordClient struct {
	KeyPair  *keyPair
	ticker   *time.Ticker
	c        *websocket.Conn
	done     chan struct{}
	interval int64
	token    string
}
type keyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func New() *discordClient {
	dc := &discordClient{
		KeyPair: &keyPair{},
		done:    make(chan struct{}),
	}
	dc.interval = 0
	dc.genKey()
	return dc
}

func (d *discordClient) Start() {
	u := url.URL{
		Scheme:   "wss",
		Host:     "remote-auth-gateway.discord.gg",
		Path:     "/",
		RawQuery: "v=1",
	}
	log.Println(u.String())
	headers := http.Header{
		"Origin": []string{"https://discord.com"},
	}
	var err error
	d.c, _, err = websocket.DefaultDialer.Dial(u.String(), headers)

	if err != nil {
		log.Println("Dial : ", err)
	}
	defer d.c.Close()

	d.done = make(chan struct{})
	go d.receive()
	d.waitloop()
}
func (d *discordClient) genKey() {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	rsaPublicKey := rsaPrivateKey.Public()
	rsaPublicKeyP := rsaPublicKey.(*rsa.PublicKey)

	d.KeyPair.privateKey = rsaPrivateKey
	d.KeyPair.publicKey = rsaPublicKeyP

}
func (d *discordClient) getEncodedPublicKey() string {
	f := new(bytes.Buffer)
	pub, err := x509.MarshalPKIXPublicKey(d.KeyPair.publicKey)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	})
	if err != nil {
		log.Fatal(err)
	}
	pubkey := f.String()
	pubkey = strings.ReplaceAll(pubkey, "-----BEGIN PUBLIC KEY-----", "")
	pubkey = strings.ReplaceAll(pubkey, "-----END PUBLIC KEY-----", "")
	pubkey = strings.Join(strings.Split(pubkey, "\n"), "")
	pubkey = strings.TrimSpace(pubkey)
	return pubkey
}
func (d *discordClient) receive() {
	defer close(d.done)
	for {
		_, message, err := d.c.ReadMessage()
		if err != nil {
			log.Println("read : ", err)
			return
		}
		m := make(map[string]interface{})
		err = json.Unmarshal(message, &m)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(m)
		switch m["op"] {
		case "hello":
			d.interval = int64(m["heartbeat_interval"].(float64))
			d.ticker = time.NewTicker(time.Duration(d.interval) * time.Millisecond)
			type initJson struct {
				Op        string `json:"op"`
				EncPubKey string `json:"encoded_public_key"`
			}
			encodedPubkey := d.getEncodedPublicKey()

			ij := initJson{
				Op:        "init",
				EncPubKey: encodedPubkey,
			}
			err = d.c.WriteJSON(ij)
			if err != nil {
				log.Println("connection error : ", err)
				return
			}

		case "nonce_proof":
			encNonceb64 := m["encrypted_nonce"].(string)
			encNonce, _ := base64.StdEncoding.DecodeString(encNonceb64)
			dec, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.KeyPair.privateKey, encNonce, nil)
			hashNonce := sha256.Sum256(dec)
			hashb64 := base64.RawURLEncoding.EncodeToString(hashNonce[:])
			type proofJson struct {
				Op    string `json:"op"`
				Proof string `json:"proof"`
			}
			pj := proofJson{
				Op:    "nonce_proof",
				Proof: hashb64,
			}
			err = d.c.WriteJSON(pj)
			if err != nil {
				log.Println("connection error : ", err)
				return
			}
		case "pending_remote_init":
			fingerPrint := m["fingerprint"].(string)
			authURL := "https://discord.com/ra/" + fingerPrint
			log.Println(authURL)

		case "pending_finish":
			encUser := m["encrypted_user_payload"].(string)
			encUserdecode, _ := base64.StdEncoding.DecodeString(encUser)
			dec, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.KeyPair.privateKey, encUserdecode, nil)
			userData := strings.Split(string(dec), ":")
			id := userData[0]
			discriminator := userData[1]
			avatar := userData[2]
			userName := userData[3]
			log.Printf("ID:%s\nDiscriminator:%s\nAvatarURL:https://cdn.discordapp.com/avatars/%s/%s.png\nUserName:%s\n", id, discriminator, id, avatar, userName)

		case "finish":
			encToken := m["encrypted_token"].(string)
			encTokendecode, _ := base64.StdEncoding.DecodeString(encToken)
			dec, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.KeyPair.privateKey, encTokendecode, nil)
			token := string(dec)
			log.Printf("Decrypted Token : %s\n", token)
			d.token = token
		}
	}
}

func (d *discordClient) waitloop() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	for {
		select {
		case <-d.done:
			log.Println("done")
			return

		case <-interrupt:
			log.Println("interrupt")
			err := d.c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-d.done:
			case <-time.After(time.Second):
			case <-d.ticker.C:
				type heartbeat struct {
					Op string `json:"op"`
				}
				hb := heartbeat{
					Op: "heartbeat",
				}
				err = d.c.WriteJSON(hb)
				if err != nil {
					log.Println("ConnectionError : ", err)
				}
			}
			return

		}
	}
}
