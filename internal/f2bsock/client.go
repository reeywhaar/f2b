// Package f2bsock speaks to a running fail2ban over its own socket: a pickled list of words
// out, a pickled (code, result) back, each ended by a marker.
//
// The same thing fail2ban-client does, without starting Python for every question: the overview
// asks several per jail, and a process each would be most of a second apiece.
package f2bsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"

	ogórek "github.com/kisielk/og-rek"
)

// end closes every message both ways; hangup, sent raw rather than pickled, asks the server to
// close the connection.
var (
	end    = []byte("<F2B_END_COMMAND>")
	hangup = []byte("<F2B_CLOSE_COMMAND>")
)

// replyMax bounds what is read back. The largest answer is a jail's banned list, and a million
// addresses is well under it.
const replyMax = 64 << 20

// ErrUnreachable means nothing answered on the socket: fail2ban is starting, stopped, or gone.
var ErrUnreachable = errors.New("fail2ban is not answering on its socket")

// Error is fail2ban refusing a command, with its own words for why.
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "fail2ban refused: " + e.Kind
	}
	return "fail2ban refused: " + e.Message
}

// Client asks one fail2ban. It holds no connection: each command dials, which is what the
// server expects and what keeps a restart of fail2ban from leaving it holding a dead one.
type Client struct {
	Path    string
	Timeout time.Duration
}

func New(path string) *Client {
	return &Client{Path: path, Timeout: 10 * time.Second}
}

// Do sends one command and returns its result, normalized: strings, int64s, float64s, bools,
// nil, []any and map[string]any.
func (c *Client) Do(ctx context.Context, words ...string) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	msg := append(Encode(words), end...)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("sending %q to fail2ban: %w", strings.Join(words, " "), err)
	}
	reply, err := readReply(conn)
	if err != nil {
		return nil, fmt.Errorf("reading fail2ban's answer to %q: %w", strings.Join(words, " "), err)
	}
	// Best effort: the answer is already here, and the server tidies up a dropped connection.
	conn.Write(append(append([]byte{}, hangup...), end...))

	return Decode(reply)
}

func readReply(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		buf.Write(chunk[:n])
		if bytes.HasSuffix(buf.Bytes(), end) {
			return bytes.TrimSuffix(buf.Bytes(), end), nil
		}
		if buf.Len() > replyMax {
			return nil, fmt.Errorf("the answer is over %d MB", replyMax>>20)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("fail2ban hung up before it finished answering")
			}
			return nil, err
		}
	}
}

// Encode pickles a list of strings, by hand: protocol 2, each one a BINUNICODE, which is
// unambiguous about being text whatever the server's default encoding is.
func Encode(words []string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x80, 2}) // PROTO 2
	b.WriteByte(']')         // EMPTY_LIST
	if len(words) > 0 {
		b.WriteByte('(') // MARK
		for _, w := range words {
			b.WriteByte('X') // BINUNICODE
			var n [4]byte
			binary.LittleEndian.PutUint32(n[:], uint32(len(w)))
			b.Write(n[:])
			b.WriteString(w)
		}
		b.WriteByte('e') // APPENDS
	}
	b.WriteByte('.') // STOP
	return b.Bytes()
}

// Decode reads fail2ban's (code, result). A nonzero code carries an exception, returned as an
// *Error.
func Decode(reply []byte) (any, error) {
	dec := ogórek.NewDecoderWithConfig(bytes.NewReader(reply), &ogórek.DecoderConfig{
		StrictUnicode: true,
	})
	raw, err := dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("fail2ban's answer is not a pickle this reads: %w", err)
	}
	pair, ok := raw.(ogórek.Tuple)
	if !ok || len(pair) != 2 {
		return nil, fmt.Errorf("fail2ban answered %T rather than a (code, result) pair", raw)
	}
	code := normalize(pair[0])
	result := pair[1]
	if c, ok := code.(int64); ok && c == 0 {
		return normalize(result), nil
	}
	return nil, exception(result)
}

// exception reads a pickled Python exception: a class called with its arguments.
func exception(v any) error {
	call, ok := v.(ogórek.Call)
	if !ok {
		return &Error{Kind: "error", Message: fmt.Sprint(normalize(v))}
	}
	var parts []string
	for _, a := range call.Args {
		parts = append(parts, fmt.Sprint(normalize(a)))
	}
	msg := strings.Join(parts, ", ")
	kind := call.Callable.Name
	// fail2ban's UnknownJailException carries only the name.
	if kind == "UnknownJailException" {
		msg = "there is no running jail " + msg
	}
	return &Error{Kind: kind, Message: msg}
}

// normalize turns what the decoder makes into plain Go values, so callers switch on a handful of
// types rather than on the pickle library's.
func normalize(v any) any {
	switch x := v.(type) {
	case nil, bool, string, float64, int64:
		return x
	case int:
		return int64(x)
	case *big.Int:
		if x.IsInt64() {
			return x.Int64()
		}
		return x.String()
	case ogórek.Bytes:
		return string(x)
	case ogórek.ByteString:
		return string(x)
	case ogórek.None:
		return nil
	case ogórek.Tuple:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(normalize(k))] = normalize(e)
		}
		return out
	case ogórek.Dict:
		out := make(map[string]any, x.Len())
		x.Iter()(func(k, e any) bool {
			out[fmt.Sprint(normalize(k))] = normalize(e)
			return true
		})
		return out
	case ogórek.Call:
		// fail2ban's addresses are a str subclass, which pickles as str called on the text.
		if x.Callable.Name == "str" && len(x.Args) == 1 {
			return normalize(x.Args[0])
		}
		return exception(x).Error()
	default:
		return fmt.Sprint(x)
	}
}

// Pairs reads fail2ban's status shape, a list of (name, value) pairs, into a map.
func Pairs(v any) map[string]any {
	out := map[string]any{}
	list, _ := v.([]any)
	for _, e := range list {
		pair, ok := e.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		if k, ok := pair[0].(string); ok {
			out[k] = pair[1]
		}
	}
	return out
}

// Strings reads a list of strings, skipping anything else.
func Strings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Int reads a number, or 0.
func Int(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

// Sorted returns a map's keys in order.
func Sorted(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
