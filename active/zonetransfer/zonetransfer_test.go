package zonetransfer

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start dns server: %v", err)
	}
	server := &dns.Server{PacketConn: conn, Handler: handler}
	go func() {
		_ = server.ActivateAndServe()
	}()
	return conn.LocalAddr().String(), func() {
		server.Shutdown()
		conn.Close()
	}
}

func TestLookupNS(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		rr, _ := dns.NewRR("example.com. 60 IN NS ns1.example.com.")
		msg.Answer = append(msg.Answer, rr)
		w.WriteMsg(msg)
	})
	addr, cleanup := startDNSServer(t, handler)
	defer cleanup()

	client := &dns.Client{Timeout: time.Second}
	names, err := lookupNS(context.Background(), client, addr, "example.com")
	if err != nil {
		t.Fatalf("lookupNS failed: %v", err)
	}
	if len(names) != 1 || names[0] != "ns1.example.com" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestAddRecordAndRecordValue(t *testing.T) {
	records := make(map[string]map[string][]string)
	rrStrings := []string{
		"www.example.com. 60 IN A 192.0.2.1",
		"www.example.com. 60 IN AAAA 2001:db8::1",
		"www.example.com. 60 IN CNAME api.example.com.",
		"example.com. 60 IN MX 10 mail.example.com.",
		"example.com. 60 IN NS ns1.example.com.",
		"example.com. 60 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600",
		"_service._tcp.example.com. 60 IN SRV 10 5 443 target.example.com.",
		"example.com. 60 IN TXT \"hello world\"",
		"example.com. 60 IN CAA 0 issue \"letsencrypt.org\"",
	}
	for _, raw := range rrStrings {
		rr, err := dns.NewRR(raw)
		if err != nil {
			t.Fatalf("failed to parse rr: %v", err)
		}
		addRecord(records, rr)
	}
	if len(records) == 0 || len(records["www.example.com"]["A"]) == 0 {
		t.Fatalf("expected records to be populated: %+v", records)
	}
}

func TestHelperFunctions(t *testing.T) {
	if sanitizeName("Example.COM.") != "example.com" {
		t.Fatalf("sanitizeName failed")
	}
	values := uniqueSorted([]string{"b", "a", "a"})
	if len(values) != 2 || values[0] != "a" {
		t.Fatalf("unexpected uniqueSorted result: %v", values)
	}
	if _, err := resolverAddress(""); err == nil {
		t.Fatalf("expected error for empty nameserver")
	}
	addr, err := resolverAddress("ns1.example.com")
	if err != nil || addr != "ns1.example.com:53" {
		t.Fatalf("unexpected resolver address: %v %v", addr, err)
	}
}

func TestLogVerbose(t *testing.T) {
	var buf bytes.Buffer
	logVerbose(Options{Verbose: true, LogWriter: &buf}, "message %s", "ok")
	if !bytes.Contains(buf.Bytes(), []byte("message ok")) {
		t.Fatalf("expected log output, got %s", buf.String())
	}
}
