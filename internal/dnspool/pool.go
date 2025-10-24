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
func AcquireMsg() *dns.Msg {
	msg := msgPool.Get().(*dns.Msg)
	resetMsg(msg)
	return msg
}

// ReleaseMsg returns a dns.Msg to the pool after resetting its buffers.
func ReleaseMsg(msg *dns.Msg) {
	if msg == nil {
		return
	}
	resetMsg(msg)
	msgPool.Put(msg)
}

func resetMsg(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.MsgHdr = dns.MsgHdr{}
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	msg.Compress = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
}
