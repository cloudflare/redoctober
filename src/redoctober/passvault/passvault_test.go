package passvault

import (
	"testing"
)

var emptyKey = make([]byte, 16)
var dummy = make([]byte, 16)

func TestUsesFlush(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Expiry: nextYear,
		Uses: 1,
		key: emptyKey,
	}

	LiveKeys["first"] = singleUse

	FlushCache()
	if len(LiveKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	
	EncryptKey(dummy, "first")

	FlushCache()
	if len(LiveKeys) != 0 {
		t.Fatalf("Error in number of live keys")
	}
}

func TestTimeFlush(t *testing.T) {
	oneSec, _ := time.ParseDuration("1s")
	one := now.Add(oneSec)

	singleUse := ActiveUser{
		Admin: true,
		Expiry: one,
		Uses: 10,
		key: emptyKey,
	}

	LiveKeys["first"] = singleUse

	FlushCache()
	if len(LiveKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first")

	FlushCache()
	if len(LiveKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	time.Sleep(oneSec)

	_, err := DecryptKey(dummy, "first")

	if err == nil {
		t.Fatalf("Error in pruning expired key")
	}
}


