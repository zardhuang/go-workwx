package workwx

import (
	"encoding/xml"
	"errors"
	"github.com/zardhuang/go-workwx/internal/lowlevel/encryptor"
	"github.com/zardhuang/go-workwx/internal/lowlevel/signature"
	"net/url"
)

func (c *WorkwxApp) FromEnvelope(body []byte) (*RxMessage, error) {
	return fromEnvelope(body)
}

func (c *WorkwxApp) VerifySignature(token string, url *url.URL, body string) bool {
	return signature.VerifyHTTPRequestSignature(token, url, body)
}

func (c *WorkwxApp) VerifyUrl(token string, encodingAESKey string, url *url.URL, body string) (string, error) {
	flag := signature.VerifyHTTPRequestSignature(token, url, body)
	if !flag {
		return "", errors.New("invalid signature")
	}
	enc, err := encryptor.NewWorkwxEncryptor(encodingAESKey)
	if err != nil {
		return "", err
	}
	echoStr := url.Query().Get("echostr")
	payload, err := enc.Decrypt([]byte(echoStr))
	if err != nil {
		return "", err
	}
	return string(payload.Msg), err
}

type XmlRxEnvelope struct {
	ToUserName string `xml:"ToUserName"`
	AgentID    string `xml:"AgentID"`
	Encrypt    string `xml:"Encrypt"`
}

type XmlEnvelope struct {
	ToUserName string
	AgentID    string
	Msg        []byte
	ReceiveID  []byte
}

func (c *WorkwxApp) ParseMessage(token string, encodingAESKey string, url *url.URL, body string) (XmlEnvelope, error) {
	enc, err := encryptor.NewWorkwxEncryptor(encodingAESKey)
	if err != nil {
		return XmlEnvelope{}, err
	}
	var x XmlRxEnvelope
	err = xml.Unmarshal([]byte(body), &x)
	if err != nil {
		return XmlEnvelope{}, err
	}

	// check signature
	if !signature.VerifyHTTPRequestSignature(token, url, x.Encrypt) {
		return XmlEnvelope{}, errors.New("invalid signature")
	}

	// decrypt message
	msg, err := enc.Decrypt([]byte(x.Encrypt))
	if err != nil {
		return XmlEnvelope{}, err
	}

	// assemble envelope to return
	return XmlEnvelope{
		ToUserName: x.ToUserName,
		AgentID:    x.AgentID,
		Msg:        msg.Msg,
		ReceiveID:  msg.ReceiveID,
	}, nil
}
