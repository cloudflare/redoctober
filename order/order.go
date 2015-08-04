package order

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/cloudflare/redoctober/hipchat"
)

const (
	NewOrder       = "%s has created an order for the label %s. requesting %s delegations for %s"
	NewOrderLink   = "@%s - https://%s?%s"
	OrderFulfilled = "%s has had order %s fulfilled."
	NewDelegation  = "%s has delegated the label %s to %s (per order %s) for %s"
)

type Order struct {
	Name string
	Num  string

	TimeRequested     time.Time
	ExpiryTime        time.Time
	DurationRequested time.Duration
	Delegated         int
	AdminsDelegated   []string
	Admins            []string
	Label             string
}

type OrderIndex struct {
	OrderFor string

	OrderId     string
	OrderOwners []string
}

// Orders represents a mapping of Order IDs to Orders. This structure
// is useful for looking up information about individual Orders and
// whether or not an order has been fulfilled. Orders that have been
// fulfilled will be removed from the structure.
type Orderer struct {
	Orders        map[string]Order
	Hipchat       hipchat.HipchatClient
	AlternateName string
}

func CreateOrder(name string, labels string, orderNum string, time time.Time, expiryTime time.Time, duration time.Duration, adminsDelegated, contacts []string, numDelegated int) (ord Order) {
	ord.Name = name
	ord.Num = orderNum
	ord.Label = labels
	ord.TimeRequested = time
	ord.ExpiryTime = expiryTime
	ord.DurationRequested = duration
	ord.AdminsDelegated = adminsDelegated
	ord.Admins = contacts
	ord.Delegated = numDelegated
	return
}

func GenerateNum() (num string) {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewOrder will create a new map of Orders
func NewOrderer(hipchatClient hipchat.HipchatClient) (o Orderer) {
	o.Orders = make(map[string]Order)
	o.Hipchat = hipchatClient
	o.AlternateName = "HipchatName"
	return
}

// notify is a generic function for using a notifier, but it checks to make
// sure that there is a notifier available, since there won't always be.
func notify(o *Orderer, msg, color string) {
	o.Hipchat.Notify(msg, color)
}
func (o *Orderer) NotifyNewOrder(name, duration, label, uses, orderNum string, owners map[string]string) {
	n := fmt.Sprintf(NewOrder, name, label, uses, duration)
	notify(o, n, hipchat.RedBackground)
	for owner, hipchatName := range owners {
		queryParams := url.Values{
			"delegator": {owner},
			"label":     {label},
			"duration":  {duration},
			"uses":      {uses},
			"ordernum":  {orderNum},
			"delegatee": {name},
		}.Encode()
		notify(o, fmt.Sprintf(NewOrderLink, hipchatName, o.Hipchat.RoHost, queryParams), hipchat.GreenBackground)
	}
}

func (o *Orderer) NotifyDelegation(delegator, label, delegatee, orderNum, duration string) {
	n := fmt.Sprintf(NewDelegation, delegator, label, delegatee, orderNum, duration)
	notify(o, n, hipchat.YellowBackground)
}
func (o *Orderer) NotifyOrderFulfilled(name, orderNum string) {
	n := fmt.Sprintf(OrderFulfilled, name, orderNum)
	notify(o, n, hipchat.PurpleBackground)
}

func (o *Orderer) FindOrder(name, label string) (string, bool) {
	for key, order := range o.Orders {
		if name != order.Name {
			continue
		}
		if label != order.Label {
			continue
		}

		return key, true
	}
	return "", false
}
