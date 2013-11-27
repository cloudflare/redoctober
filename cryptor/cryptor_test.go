// cryptor_test.go: tests for core.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package cryptor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestHash(t *testing.T) {
	decryptJson := []byte("{\"Version\":1,\"VaultId\":529853895,\"KeySet\":[{\"Name\":[\"Bob\",\"Alice\"],\"Key\":\"2j3tI2PBFBbwFX0BlQdUuA==\"},{\"Name\":[\"Bob\",\"Carol\"],\"Key\":\"yLSSB/U6+5rc1E+gjGXT4w==\"},{\"Name\":[\"Alice\",\"Bob\"],\"Key\":\"DDlWHF7szzISuXWaEz8llQ==\"},{\"Name\":[\"Alice\",\"Carol\"],\"Key\":\"TkA13aPrYFNbveIbl0qdww==\"},{\"Name\":[\"Carol\",\"Bob\"],\"Key\":\"KXm0uObmRJ2ZvSYEWPwk2A==\"},{\"Name\":[\"Carol\",\"Alice\"],\"Key\":\"L9c+PqtxPh9y6apRvtbCQw==\"}],\"KeySetRSA\":{\"Alice\":{\"Key\":\"fj5mqnq7y5KCafCGT1I51xI5JsX746+9TTSsp/8ybf3iZjhFzSlwP3aNmsOx3SUKTmZlfs+b+MeD4eKJ2uKBFzQHAIPO0fwoiCDKHhKH6KsolNq4+jgpkLAMOLsQGs8g6BhJy6bCFRjZVc3IdlQABPM6PkTbuSvKhn9atDFwZQD5TJBISi7d2hw4LradtLITbNqwiFMTQQ9+psXzyavY8H3LNHKGgf5Od7IpthEQPCHi4nw7X/YVRTEMfoIVcMcKOwYjlC45/VJEHK9Zy3DSiLBzjmr57YNIVjw8YZY5DGBWqbgu51RUbIcrqyLphBhXoBRu4R+yrhygBNWbvkkifA==\"},\"Bob\":{\"Key\":\"HTYiZ18sf721cAN1LRNkJ/+L4AKWilMrkMyNiBjWcl9HRTVPNXITqQBXd0fBggGNPiZr6VQTySK4ZFvJKGDGiz17Te/ToDn8Yk/B9cqMsN5fHoQtXvl8IZo2wioA67ccAJ1gHMMNpPyLdF43SQqgI+XaQ2lMSYLMfxxDmBBOQ1SWAto0BDRdnsqpwUwIPKQ9Y3/1osmrjLmJoAC3MPplexYWhexNwJtSd+mFdVZ3Qe4x9RsRHcN/myihOt/67V60qzs13F0RZkMSDzj5Ddg+1KVNJZY9dmolPNkAZj8z20L9uzpatrTYTR6A8q/sRn+inO7ZQVQ00XO6q6lYYQzxnw==\"},\"Carol\":{\"Key\":\"ItrvS02nSfbcA2fl1L1i61xqPEDKRdsrYe3+UCbkT+ipheiQRPSuikbzeV2kshn4yJDeku5bmTNqW8HSGtU7GTgCoIWV8WmEf4w6ovzShPbu+VrIZvRz3wjh2oYHT/gtPVAQnBa/71FeoBNxy5l/hBcUmBky43j83Mlt2+8QZx6PEUDmpaPQemVh99+C20nQtkAUFeMc2Ge4y7RlHSxtfABvwlXx1NzCD40nyJfF1SjV/fZh/E2Al4Tavx6DOJkYGoJ2mp7XBvX0IF2tp8T3U5VpnTek/WuNrLL9z7/jqzWh87lZ5KheWXhGkU1BNH4lfIj43pDkSy50aDvS0zYfHQ==\"}},\"IV\":\"58r9Mz8e06mItBG9nSV/0Q==\",\"Data\":\"QE9ZhcGXNXauUdMk04biUGy1SoP5H2nF/j2JjiiVFKPdIdRp/Gc+AZvUI9n22ZM4q+zDiJz7qvK4bKaPpXhTmGP0XheaFUukeVNS9STMoTbNcY/ZtVOz6hizUPF7gSq388QPUsT+Axml3rEUTWOhnw==\",\"Signature\":\"ItiAS26GFlbM5szJr5HXVB9BR+s=\"}")

	var encrypted EncryptedData
	if err := json.Unmarshal(decryptJson, &encrypted); err != nil {
		t.Fatalf("Error unmarshalling json, %v", err)
	}

	var hmacKey, _ = base64.StdEncoding.DecodeString("Qugc5ZQ0vC7KQSgmDHTVgQ==")
	var signature = append([]byte{}, encrypted.Signature...)

	expectedSig := computeHmac(hmacKey, encrypted)

	if diff := bytes.Compare(signature, expectedSig); diff != 0 {
		t.Fatalf("Error comparing signature %v", base64.StdEncoding.EncodeToString(expectedSig))
	}

	// change version and check hmac
	encrypted.Version = 2
	unexpectedSig := computeHmac(hmacKey, encrypted)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}
	encrypted.Version = 1

	// change vaultid and check hmac
	encrypted.VaultId = 529853896
	unexpectedSig = computeHmac(hmacKey, encrypted)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}
	encrypted.VaultId = 529853895

	// swap two records and check hmac
	encrypted.KeySet[0], encrypted.KeySet[1] = encrypted.KeySet[1], encrypted.KeySet[0]
	unexpectedSig = computeHmac(hmacKey, encrypted)

	if diff := bytes.Compare(signature, unexpectedSig); diff != 0 {
		t.Fatalf("Error comparing signature %v, %v",
			base64.StdEncoding.EncodeToString(unexpectedSig),
			base64.StdEncoding.EncodeToString(signature))
	}

	// delete RSA key and check hmac
	encrypted.Version = 1
	delete(encrypted.KeySetRSA, "Carol")
	unexpectedSig = computeHmac(hmacKey, encrypted)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}

}
