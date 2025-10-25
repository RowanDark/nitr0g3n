package bruteforce

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestDNSServer(t *testing.T, responses map[string][]string) (string, func()) {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		hostname := strings.ToLower(r.Question[0].Name)
		if answers, ok := responses[hostname]; ok {
			for _, ans := range answers {
				if ip := net.ParseIP(ans); ip != nil {
					rr := &dns.A{Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}
					msg.Answer = append(msg.Answer, rr)
				} else {
					rr := &dns.CNAME{Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: dns.Fqdn(ans)}
					msg.Answer = append(msg.Answer, rr)
				}
			}
		} else {
			msg.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(msg)
	})

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test dns server: %v", err)
	}

	server := &dns.Server{PacketConn: conn, Handler: mux}
	go func() {
		_ = server.ActivateAndServe()
	}()

	cleanup := func() {
		_ = server.Shutdown()
		_ = conn.Close()
	}
	return conn.LocalAddr().String(), cleanup
}

func TestRunBruteforce(t *testing.T) {
	addr, cleanup := startTestDNSServer(t, map[string][]string{
		"www.example.com.": {"192.0.2.1"},
		"api.example.com.": {"alias.example.com"},
	})
	defer cleanup()

	dir := t.TempDir()
	wordlist := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlist, []byte("www\napi\n"), 0o644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results, err := Run(ctx, Options{
		Domain:       "example.com",
		WordlistPath: wordlist,
		Permutations: false,
		DNSServer:    addr,
		Timeout:      time.Second,
		Workers:      2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Subdomain != "api.example.com" || results[1].Subdomain != "www.example.com" {
		t.Fatalf("unexpected order or subdomains: %v", results)
	}
}

func TestRunRequiresDomain(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatalf("expected error when domain missing")
	}
}

func TestLoadWordsDefaults(t *testing.T) {
	words, err := loadWords("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(words) == 0 {
		t.Fatalf("expected embedded wordlist to contain entries")
	}
}

func TestBuildLabelsWithPermutations(t *testing.T) {
        labels := buildLabels([]string{"admin"}, true, 0)
	if len(labels) == 0 {
		t.Fatalf("expected labels to be generated")
	}
	seenAdmin := false
	for _, label := range labels {
		if label == "admin" {
			seenAdmin = true
			break
		}
	}
	if !seenAdmin {
		t.Fatalf("expected base label to be present: %v", labels)
	}
}

func TestNumberVariants(t *testing.T) {
	variants := numberVariants()
	if len(variants) != 100 { // 0-99 inclusive
		t.Fatalf("unexpected variant count: %d", len(variants))
	}
	if variants[0] != "0" || variants[len(variants)-1] != "99" {
		t.Fatalf("unexpected edge variants: %v", []string{variants[0], variants[len(variants)-1]})
	}
}
