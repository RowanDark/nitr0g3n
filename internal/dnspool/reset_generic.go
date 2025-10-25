//go:build !amd64

package dnspool

import "github.com/miekg/dns"

func resetMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.MsgHdr = dns.MsgHdr{}
	for i := range msg.Question {
		msg.Question[i] = dns.Question{}
	}
	msg.Question = msg.Question[:0]
	for i := range msg.Answer {
		msg.Answer[i] = dns.RR(nil)
	}
	msg.Answer = msg.Answer[:0]
	for i := range msg.Ns {
		msg.Ns[i] = dns.RR(nil)
	}
	msg.Ns = msg.Ns[:0]
	for i := range msg.Extra {
		msg.Extra[i] = dns.RR(nil)
	}
	msg.Extra = msg.Extra[:0]
	msg.Compress = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
}
