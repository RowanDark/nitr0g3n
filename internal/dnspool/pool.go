package dnspool

import (
	"sync"

	"github.com/miekg/dns"
)

var msgPool = sync.Pool{
	New: func() any {
		return &dns.Msg{}
	},
}

// AcquireMsg obtains a dns.Msg from the pool and resets it to a clean state.
//
//go:inline
func AcquireMsg() *dns.Msg {
	msg := msgPool.Get().(*dns.Msg)
	resetMessage(msg)
	return msg
}

// ReleaseMsg returns a dns.Msg to the pool after resetting its buffers.
//
//go:inline
func ReleaseMsg(msg *dns.Msg) {
	if msg == nil {
		return
	}
	resetMessage(msg)
	msgPool.Put(msg)
}
