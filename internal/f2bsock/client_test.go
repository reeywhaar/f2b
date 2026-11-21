package f2bsock

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Pickled by CPython at protocol 5, which is what fail2ban answers in: its highest.
var fixtures = map[string]string{
	"status":     "8005953b000000000000004b005d94288c0e4e756d626572206f66206a61696c944b0286948c094a61696c206c697374948c0c6d61696c696f2c20737368649486946586942e",
	"jailStatus": "800595d1000000000000004b005d94288c0646696c746572945d94288c1043757272656e746c79206661696c6564944b0186948c0c546f74616c206661696c6564944b0786948c0946696c65206c697374945d948c1d2f72656d6f74656c6f67732f646f636b65722f6d61696c696f2e6c6f67946186946586948c07416374696f6e73945d94288c1043757272656e746c792062616e6e6564944b0186948c0c546f74616c2062616e6e6564944b0386948c0e42616e6e6564204950206c697374945d948c0b3230332e302e3131332e37946186946586946586942e",
	"banned":     "80059532000000000000004b005d94287d948c066d61696c696f945d948c0b3230332e302e3131332e379461737d948c0473736864945d94736586942e",
	"refused":    "80059538000000000000004b018c086275696c74696e73948c0a56616c75654572726f729493948c12496e76616c69642049502061646472657373948594529486942e",
	"pong":       "8005950c000000000000004b008c04706f6e679486942e",
	"three":      "80059507000000000000004b004b0386942e",
	// fail2ban's own banned answer, its addresses being IPAddr, taken from fail2ban 1.1.0.
	"bannedIPAddr": "8005954e000000000000004b005d947d948c03617070945d94288c086275696c74696e73948c037374729493948c0b3230332e302e3131332e39948594529468068c0b323030313a6462383a3a35948594529465736186942e",
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := hex.DecodeString(fixtures[name])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStatusDecodesToPairs(t *testing.T) {
	v, err := Decode(fixture(t, "status"))
	if err != nil {
		t.Fatal(err)
	}
	p := Pairs(v)
	if Int(p["Number of jail"]) != 2 || p["Jail list"] != "mailio, sshd" {
		t.Fatalf("got %#v", p)
	}
}

func TestAJailsStatusDecodesToNestedPairs(t *testing.T) {
	v, err := Decode(fixture(t, "jailStatus"))
	if err != nil {
		t.Fatal(err)
	}
	p := Pairs(v)
	filter, actions := Pairs(p["Filter"]), Pairs(p["Actions"])
	if Int(filter["Total failed"]) != 7 || Int(actions["Currently banned"]) != 1 {
		t.Fatalf("got %#v", p)
	}
	if got := Strings(actions["Banned IP list"]); !reflect.DeepEqual(got, []string{"203.0.113.7"}) {
		t.Fatalf("banned list %#v", got)
	}
	if got := Strings(filter["File list"]); !reflect.DeepEqual(got, []string{"/remotelogs/docker/mailio.log"}) {
		t.Fatalf("file list %#v", got)
	}
}

func TestBannedDecodesToAListOfOneEntryMaps(t *testing.T) {
	v, err := Decode(fixture(t, "banned"))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]any{"mailio": []any{"203.0.113.7"}},
		map[string]any{"sshd": []any{}},
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("got %#v", v)
	}
}

func TestFail2bansAddressesDecodeToStrings(t *testing.T) {
	v, err := Decode(fixture(t, "bannedIPAddr"))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{map[string]any{"app": []any{"203.0.113.9", "2001:db8::5"}}}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("got %#v", v)
	}
}

func TestANonzeroCodeIsAnErrorCarryingTheExceptionsWords(t *testing.T) {
	_, err := Decode(fixture(t, "refused"))
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("got %v", err)
	}
	if refusal.Kind != "ValueError" || refusal.Message != "Invalid IP address" {
		t.Fatalf("got %#v", refusal)
	}
}

func TestEncodeWritesAListOfUnicodeStrings(t *testing.T) {
	got := Encode([]string{"set", "sshd", "banip", "203.0.113.7"})
	want := []byte("\x80\x02](X\x03\x00\x00\x00setX\x04\x00\x00\x00sshdX\x05\x00\x00\x00banipX\x0b\x00\x00\x00203.0.113.7e.")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

// A stand-in fail2ban: reads one message to the marker, answers with a fixture, then expects the
// raw hang-up.
func TestDoSendsAMessageAndReadsTheAnswer(t *testing.T) {
	path := filepath.Join(shortDir(t), "f.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		msg, _ := readReply(conn)
		got <- msg
		conn.Write(append(fixture(t, "pong"), end...))
		readReply(conn)
	}()

	v, err := New(path).Do(context.Background(), "ping")
	if err != nil {
		t.Fatal(err)
	}
	if v != "pong" {
		t.Fatalf("answer %#v", v)
	}
	if sent := <-got; !bytes.Equal(sent, Encode([]string{"ping"})) {
		t.Fatalf("sent %q", sent)
	}
}

func TestDoOnNoSocketIsUnreachable(t *testing.T) {
	_, err := New(filepath.Join(t.TempDir(), "none.sock")).Do(context.Background(), "ping")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v", err)
	}
}

// shortDir is a temporary directory with a short path: a socket's path is limited to about a
// hundred bytes, and t.TempDir's carries the test's name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "f2b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
