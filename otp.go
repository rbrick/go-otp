package otp

import (
	"crypto"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// 30 second interval
	DefaultInterval = 30

	OtpAuthScheme = "otpauth"
)

type Counter interface {
	Count() int64
}

type TimeCounter struct {
	Interval, Step int
}

func (t *TimeCounter) Count() int64 {
	return int64(math.Floor(float64(time.Now().Unix()-int64(t.Step)) / float64(t.Interval)))
}

type OTP interface {
	Counter() Counter
	Hash() crypto.Hash
	GenerateCode(key string, count int64, tokenLen int) (string, error)
	VerifyCode(code, key string, skew, tokenLen int) bool
}

type HOTP struct {
	counter  Counter
	hashAlgo crypto.Hash
}

func (h *HOTP) Counter() Counter {
	return h.counter
}

func (h *HOTP) Hash() crypto.Hash {
	return h.hashAlgo
}

func (h *HOTP) GenerateCode(key string, count int64, tokenLen int) (string, error) {
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(key))

	if err != nil {
		return "", err
	}

	hmacResult := genKey(h.Hash(), b, count)

	code := strconv.Itoa(truncate(hmacResult) % int(math.Pow10(tokenLen)))

	// pad the string on the left if necessary
	if len(code) < tokenLen {
		code = strings.Repeat("0", tokenLen-len(code)) + code
	}

	return code, nil
}

func (h *HOTP) VerifyCode(code, key string, skew, tokenLen int) bool {
	currentCount := h.counter.Count()
	currentCode, _ := h.GenerateCode(key, currentCount, tokenLen)

	if currentCode == code {
		return true
	}

	for i := 1; i < skew; i++ {
		behind, _ := h.GenerateCode(key, currentCount-int64(i), tokenLen)
		ahead, _ := h.GenerateCode(key, currentCount+int64(i), tokenLen)

		if behind == code || ahead == code {
			return true
		}
	}

	return false
}

func truncate(b []byte) int {
	offset := int(b[len(b)-1]) & 0xf
	return int(b[offset])&0x7f<<24 |
		int(b[offset+1])&0xff<<16 |
		int(b[offset+2])&0xff<<8 |
		int(b[offset+3])&0xff

}

func genKey(hasher crypto.Hash, key []byte, count int64) []byte {
	hmacHash := hmac.New(hasher.New, key)
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, uint64(count))
	hmacHash.Write(encoded)
	return hmacHash.Sum(nil)
}

func NewTOTP(hash crypto.Hash, interval, step int) OTP {
	return &HOTP{
		counter: &TimeCounter{
			Interval: interval,
			Step:     step,
		},
		hashAlgo: hash,
	}
}

func DefaultTOTP() OTP {
	return NewTOTP(crypto.SHA1, DefaultInterval, 0)
}

type AuthURL struct {
	Type      string
	Label     string
	Secret    string
	Issuer    string
	Algorithm string
	Counter   int
	Digits    int
	Period    int
}

func (o *AuthURL) String() string {
	uri := &url.URL{
		Scheme:   "otpauth",
		Host:     o.Type,
		Path:     o.Label,
		RawQuery: o.values().Encode(),
	}
	return uri.String()
}

func (o *AuthURL) values() url.Values {
	v := url.Values{}

	v.Add("secret", o.Secret)

	if o.Issuer != "" {
		v.Add("issuer", o.Issuer)
	}

	if o.Algorithm != "" {
		v.Add("algorithm", o.Algorithm)
	}

	if o.Counter != 0 {
		v.Add("counter", strconv.Itoa(o.Counter))
	}

	if o.Digits != 0 {
		v.Add("digits", strconv.Itoa(o.Digits))
	}

	if o.Period != 0 {
		v.Add("period", strconv.Itoa(o.Period))
	}

	return v
}
