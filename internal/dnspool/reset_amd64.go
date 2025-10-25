//go:build amd64

package dnspool

import "github.com/miekg/dns"

//go:inline
func resetMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.MsgHdr = dns.MsgHdr{}
	if len(msg.Question) > 0 {
		clear(msg.Question)
		msg.Question = msg.Question[:0]
	}
	if len(msg.Answer) > 0 {
		clear(msg.Answer)
		msg.Answer = msg.Answer[:0]
	}
	if len(msg.Ns) > 0 {
		clear(msg.Ns)
		msg.Ns = msg.Ns[:0]
	}
	if len(msg.Extra) > 0 {
		clear(msg.Extra)
		msg.Extra = msg.Extra[:0]
	}
	msg.Compress = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
}
