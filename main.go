package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------- style ----------

var (
	cBg   = lipgloss.Color("#1a1b26")
	cFg   = lipgloss.Color("#c0caf5")
	cAcc  = lipgloss.Color("#e0956c")
	cDim  = lipgloss.Color("#565f89")
	cWarn = lipgloss.Color("#f7768e")

	base  = lipgloss.NewStyle().Background(cBg).Foreground(cFg)
	sFg   = base
	sBold = base.Bold(true)
	sDim  = base.Foreground(cDim)
	sAcc  = base.Foreground(cAcc)
	sAccB = base.Foreground(cAcc).Bold(true)
	sWarn = base.Foreground(cWarn)
	sSel  = base.Foreground(cAcc).Bold(true)
)

func sp(n int) string {
	if n <= 0 {
		return ""
	}
	return base.Render(strings.Repeat(" ", n))
}

// ---------- classification ----------

var localNames = map[string]bool{
	"sharingd": true, "rapportd": true, "netbiosd": true,
	"mdnsresponder": true, "jellyfin": true, "remote mouse": true,
}

func isTunnel(n string) bool {
	l := strings.ToLower(n)
	return strings.Contains(l, "cloudflarewarp") || strings.Contains(l, "vpn") ||
		strings.Contains(l, "tunnel") || strings.Contains(l, "wireguard")
}

func isLocal(n string) bool { return localNames[strings.ToLower(n)] }

func groupName(n string) string {
	n = strings.TrimSpace(n)
	if strings.HasPrefix(n, "com.apple.WebKi") || n == "Safari" {
		return "Safari"
	}
	if i := strings.Index(n, " Helper"); i > 0 {
		n = n[:i]
	} else {
		for _, suf := range []string{" Helpe", " Help", " Hel", " He", " H"} {
			if strings.HasSuffix(n, suf) {
				n = strings.TrimSuffix(n, suf)
				break
			}
		}
	}
	n = strings.TrimSuffix(n, " Browser")
	return strings.TrimSpace(n)
}

// ---------- nettop ----------

type connRow struct {
	ip      string
	in, out float64
}

type procRow struct {
	name             string
	in, out, rtx, oo float64
	conns            []connRow
}

// remote endpoint of "tcp6 a.b.c.port<->ip.port" / "tcp4 a:port<->ip:port"
func parseRemote(field string) (string, bool) {
	sp := strings.IndexByte(field, ' ')
	arrow := strings.Index(field, "<->")
	if sp < 0 || arrow < 0 {
		return "", false
	}
	proto, rem := field[:sp], field[arrow+3:]
	sep := ":"
	if strings.HasSuffix(proto, "6") {
		sep = "."
	}
	if i := strings.LastIndex(rem, sep); i > 0 {
		rem = rem[:i]
	}
	ip := net.ParseIP(rem)
	if ip == nil {
		// nettop sometimes prints a resolved hostname instead of an IP
		if strings.Contains(rem, ".") && !strings.Contains(rem, "*") {
			return strings.ToLower(rem), true
		}
		return "", false
	}
	return normIP(ip), true
}

var nat64 = net.ParseIP("64:ff9b::")

func normIP(ip net.IP) string {
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil && string(v6[:12]) == string(nat64.To16()[:12]) {
		return net.IP(v6[12:16]).String()
	}
	return ip.String()
}

var cfNet = func() *net.IPNet { _, n, _ := net.ParseCIDR("2606:4700::/32"); return n }()

// matchKeys: exact IP, its IPv6 /64, and for Cloudflare the per-site hextets
// (Cloudflare rotates hextets 3,5,6 per lookup but keeps 4,7,8 stable for a zone).
func matchKeys(s string) []string {
	keys := []string{s}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return keys
	}
	b := ip.To16()
	keys = append(keys, "p64:"+net.IP(append(b[:8:8], make([]byte, 8)...)).String())
	if cfNet.Contains(ip) {
		keys = append(keys, fmt.Sprintf("cf:%x:%x:%x", b[6:8], b[12:14], b[14:16]))
	}
	return keys
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return s == "localhost" || strings.HasSuffix(s, ".local")
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

type sampleMsg struct{ rows []procRow }
type nettopErrMsg struct{ err error }

func runNettop(ctx context.Context, ch chan<- tea.Msg) {
	// nettop block-buffers on a pipe; give it a pty via script(1).
	// No -P: we want per-connection rows under each process row.
	cmd := exec.CommandContext(ctx, "script", "-q", "/dev/null",
		"nettop", "-d", "-L", "0", "-s", "1", "-x", "-J", "bytes_in,bytes_out,re-tx,rx_ooo")
	out, err := cmd.StdoutPipe()
	if err != nil {
		ch <- nettopErrMsg{err}
		return
	}
	if err := cmd.Start(); err != nil {
		ch <- nettopErrMsg{err}
		return
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	idx := map[string]int{}
	var rows []procRow
	first := true
	emit := func() {
		if len(rows) > 0 {
			if !first {
				ch <- sampleMsg{rows}
			}
			first = false
		}
		rows = nil
	}
	get := func(f []string, k string) float64 {
		i, ok := idx[k]
		if !ok || i >= len(f) {
			return 0
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(f[i]), 64)
		return v
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		f := strings.Split(line, ",")
		if strings.HasPrefix(line, ",") {
			emit()
			idx = map[string]int{}
			for i, h := range f {
				idx[strings.TrimSpace(h)] = i
			}
			continue
		}
		if len(idx) == 0 {
			continue
		}
		if len(f[0]) > 5 && (strings.HasPrefix(f[0], "tcp") || strings.HasPrefix(f[0], "udp")) && f[0][4] == ' ' {
			if len(rows) == 0 {
				continue
			}
			in, out := get(f, "bytes_in"), get(f, "bytes_out")
			if in+out == 0 {
				continue
			}
			if ip, ok := parseRemote(f[0]); ok {
				p := &rows[len(rows)-1]
				p.conns = append(p.conns, connRow{ip, in, out})
			}
			continue
		}
		raw := f[0]
		if i := strings.LastIndex(raw, "."); i > 0 {
			raw = raw[:i]
		}
		rows = append(rows, procRow{
			name: raw,
			in:   get(f, "bytes_in"), out: get(f, "bytes_out"),
			rtx: get(f, "re-tx"), oo: get(f, "rx_ooo"),
		})
	}
	ch <- nettopErrMsg{fmt.Errorf("nettop exited")}
}

func waitMsg(ch <-chan tea.Msg) tea.Cmd { return func() tea.Msg { return <-ch } }

// ---------- ping ----------

type pingMsg struct {
	ms float64
	ok bool
}
type pingTickMsg struct{}

var pingRe = regexp.MustCompile(`time[=<]([0-9.]+) ?ms`)

func doPing(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		out, _ := exec.CommandContext(ctx, "ping", "-c1", "-t1", "1.1.1.1").CombinedOutput()
		m := pingRe.FindSubmatch(out)
		if m == nil {
			return pingMsg{}
		}
		v, err := strconv.ParseFloat(string(m[1]), 64)
		return pingMsg{v, err == nil}
	}
}

func pingTick() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return pingTickMsg{} })
}

// ---------- networkQuality ----------

type nqMsg struct {
	dl, ul, rpm float64
	at          time.Time
	err         error
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	case map[string]any:
		for _, k := range []string{"value", "rpm"} {
			if x, ok := t[k]; ok {
				return num(x)
			}
		}
	}
	return 0
}

func runNQ(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		out, err := exec.CommandContext(ctx, "networkQuality", "-c").Output()
		if err != nil {
			return nqMsg{err: err, at: time.Now()}
		}
		var j map[string]any
		if err := json.Unmarshal(out, &j); err != nil {
			return nqMsg{err: err, at: time.Now()}
		}
		return nqMsg{dl: num(j["dl_throughput"]), ul: num(j["ul_throughput"]), rpm: num(j["responsiveness"]), at: time.Now()}
	}
}

// ---------- destinations: reverse DNS ----------

type rdnsCache struct {
	mu      sync.Mutex
	names   map[string]string
	pending map[string]bool
	sem     chan struct{}
}

var rdns = &rdnsCache{names: map[string]string{}, pending: map[string]bool{}, sem: make(chan struct{}, 8)}

// lookup returns the cached PTR name ("" if none/unknown yet) and kicks off a lookup if needed.
func (r *rdnsCache) lookup(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.names[ip]; ok {
		return n
	}
	if !r.pending[ip] {
		r.pending[ip] = true
		go func() {
			r.sem <- struct{}{}
			defer func() { <-r.sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			n := ""
			if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
				n = strings.TrimSuffix(names[0], ".")
			}
			r.mu.Lock()
			r.names[ip] = n
			delete(r.pending, ip)
			r.mu.Unlock()
		}()
	}
	return ""
}

var twoPartTLD = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "com.au": true, "net.au": true, "co.in": true,
	"co.jp": true, "com.br": true, "co.nz": true, "com.sg": true, "co.za": true, "com.tr": true,
}

func regDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(host) != nil {
		return host
	}
	p := strings.Split(host, ".")
	if len(p) <= 2 {
		return host
	}
	if twoPartTLD[strings.Join(p[len(p)-2:], ".")] {
		return strings.Join(p[len(p)-3:], ".")
	}
	return strings.Join(p[len(p)-2:], ".")
}

// CDN / infra domain -> site domains a tab would be on
var cdnAlias = map[string][]string{
	"googlevideo.com": {"youtube.com"}, "ytimg.com": {"youtube.com"}, "ggpht.com": {"youtube.com"},
	"1e100.net": {"youtube.com", "google.com"}, "gstatic.com": {"google.com", "youtube.com"},
	"googleusercontent.com": {"google.com"},
	"nflxvideo.net":         {"netflix.com"}, "nflxso.net": {"netflix.com"}, "nflxext.com": {"netflix.com"},
	"fbcdn.net": {"facebook.com", "instagram.com"}, "cdninstagram.com": {"instagram.com"},
	"twimg.com": {"x.com", "twitter.com"}, "redd.it": {"reddit.com"}, "redditmedia.com": {"reddit.com"},
	"redditstatic.com": {"reddit.com"}, "ttvnw.net": {"twitch.tv"}, "jtvnw.net": {"twitch.tv"},
	"scdn.co": {"spotify.com"}, "spotifycdn.com": {"spotify.com"}, "whatsapp.net": {"whatsapp.com"},
	"discordapp.net": {"discord.com"}, "discordapp.com": {"discord.com"}, "tiktokcdn.com": {"tiktok.com"},
	"githubusercontent.com": {"github.com"}, "githubassets.com": {"github.com"},
	"licdn.com": {"linkedin.com"}, "sndcdn.com": {"soundcloud.com"}, "vimeocdn.com": {"vimeo.com"},
	// org labels from the IP-range table
	"google":    {"youtube.com", "google.com"},
	"meta":      {"facebook.com", "instagram.com", "whatsapp.com"},
	"anthropic": {"claude.ai", "anthropic.com"},
	"netflix":   {"netflix.com"},
	"github":    {"github.com"},
	"apple":     {"apple.com", "icloud.com"},
	"microsoft": {"microsoft.com", "live.com", "office.com", "bing.com"},
	"telegram":  {"telegram.org", "t.me"},
	"discord":   {"discord.com"},
}

// ---------- known IP ranges ----------

// Coarse ownership of big networks, for IPs with no useful reverse DNS.
// Best-effort and static; most-specific prefix wins.
var orgRanges = map[string][]string{
	"anthropic":  {"160.79.104.0/23", "2607:6bc0::/48"},
	"meta":       {"31.13.24.0/21", "31.13.64.0/18", "157.240.0.0/16", "179.60.192.0/22", "185.60.216.0/22", "129.134.0.0/16", "2a03:2880::/32"},
	"google":     {"142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16", "216.58.192.0/19", "74.125.0.0/16", "64.233.160.0/19", "173.194.0.0/16", "209.85.128.0/17", "108.177.0.0/17", "2001:4860::/32", "2404:6800::/32", "2607:f8b0::/32", "2a00:1450::/32", "2800:3f0::/32", "2c0f:fb50::/32"},
	"gcp":        {"34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/12", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13", "2600:1900::/28"},
	"cloudflare": {"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "198.41.128.0/17", "1.1.1.0/24", "1.0.0.0/24", "2606:4700::/32", "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32"},
	"apple":      {"17.0.0.0/8", "2620:149::/32", "2403:300::/32", "2a01:b740::/32"},
	"aws":        {"3.0.0.0/9", "18.128.0.0/9", "34.192.0.0/10", "52.0.0.0/11", "54.64.0.0/11", "54.144.0.0/12", "44.192.0.0/11", "2600:1f00::/24"},
	"cloudfront": {"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "52.84.0.0/15", "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16", "143.204.0.0/16", "2600:9000::/28"},
	"microsoft":  {"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.96.0.0/12", "52.112.0.0/14", "204.79.197.0/24", "2603:1000::/24", "2620:1ec::/36"},
	"akamai":     {"23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "104.64.0.0/10", "184.24.0.0/13", "96.16.0.0/15", "2600:1400::/24", "2a02:26f0::/29"},
	"fastly":     {"151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/17", "2a04:4e40::/29"},
	"netflix":    {"198.38.96.0/19", "198.45.48.0/20", "45.57.0.0/17", "23.246.0.0/18", "2a00:86c0::/32", "2620:10c:7000::/44"},
	"github":     {"140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22", "2a0a:a440::/29"},
	"telegram":   {"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/21", "91.108.16.0/21", "91.108.56.0/22", "2001:67c:4e8::/48", "2001:b28:f23c::/46"},
	"discord":    {"162.159.128.0/19"},
}

type orgNet struct {
	n    *net.IPNet
	bits int
	name string
}

var orgNets = func() []orgNet {
	var out []orgNet
	for name, cidrs := range orgRanges {
		for _, c := range cidrs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				b, _ := n.Mask.Size()
				out = append(out, orgNet{n, b, name})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bits > out[j].bits })
	return out
}()

func orgFor(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	for _, o := range orgNets {
		if o.n.Contains(ip) {
			return o.name
		}
	}
	return ""
}

// ---------- browser tabs ----------

var browsers = []struct{ group, app, titleProp string }{
	{"Brave", "Brave Browser", "title"},
	{"Google Chrome", "Google Chrome", "title"},
	{"Microsoft Edge", "Microsoft Edge", "title"},
	{"Arc", "Arc", "title"},
	{"Safari", "Safari", "name"},
}

type tabInfo struct{ browser, title, domain string }

type tabsMsg struct {
	tabs  []tabInfo
	ipTab map[string][]int
	err   string
}
type tabsTickMsg struct{}

var (
	fwdMu    sync.Mutex
	fwdCache = map[string]struct {
		ips []string
		at  time.Time
	}{}
)

func resolveHost(h string) []string {
	fwdMu.Lock()
	c, ok := fwdCache[h]
	fwdMu.Unlock()
	if ok && time.Since(c.at) < 2*time.Minute {
		return c.ips
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var ips []string
	if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h); err == nil {
		for _, a := range addrs {
			ips = append(ips, normIP(a.IP))
		}
	}
	fwdMu.Lock()
	fwdCache[h] = struct {
		ips []string
		at  time.Time
	}{ips, time.Now()}
	fwdMu.Unlock()
	return ips
}

func pollTabs(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		var tabs []tabInfo
		hostsOf := map[string][]int{}
		var errs []string
		for _, b := range browsers {
			if exec.CommandContext(ctx, "pgrep", "-xq", b.app).Run() != nil {
				continue
			}
			script := fmt.Sprintf(`set d to character id 9
set o to ""
tell application %q
	repeat with w in windows
		repeat with t in tabs of w
			try
				set o to o & (%s of t) & d & (URL of t) & linefeed
			end try
		end repeat
	end repeat
end tell
return o`, b.app, b.titleProp)
			tctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			out, err := exec.CommandContext(tctx, "osascript", "-e", script).CombinedOutput()
			cancel()
			if err != nil {
				if strings.Contains(string(out), "-1743") {
					errs = append(errs, "allow Automation for "+b.app)
				}
				continue
			}
			for _, ln := range strings.Split(string(out), "\n") {
				parts := strings.SplitN(ln, "\t", 2)
				if len(parts) != 2 {
					continue
				}
				u, err := url.Parse(strings.TrimSpace(parts[1]))
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
					continue
				}
				tabs = append(tabs, tabInfo{b.group, strings.TrimSpace(parts[0]), regDomain(u.Hostname())})
				h := u.Hostname()
				hostsOf[h] = append(hostsOf[h], len(tabs)-1)
			}
		}
		// forward-resolve tab hosts so connection IPs can be matched to tabs
		ipTab := map[string][]int{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		n := 0
		for h, idxs := range hostsOf {
			if n++; n > 80 {
				break
			}
			wg.Add(1)
			go func(h string, idxs []int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				for _, ip := range resolveHost(h) {
					mu.Lock()
					for _, k := range matchKeys(ip) {
						ipTab[k] = append(ipTab[k], idxs...)
					}
					mu.Unlock()
				}
			}(h, idxs)
		}
		wg.Wait()
		return tabsMsg{tabs, ipTab, strings.Join(errs, ", ")}
	}
}

func tabsTick() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return tabsTickMsg{} })
}

// ---------- refresh ----------

type tickMsg struct{}

func tick() tea.Cmd { return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} }) }

// ---------- model ----------

type dest struct {
	label, title string
	down, up     float64 // bits/s
	lastActive   time.Time
}

type app struct {
	name       string
	down, up   float64 // bits/s
	lastActive time.Time
	local      bool
	dests      map[string]*dest
}

func (a *app) activeDests(now time.Time) []*dest {
	var out []*dest
	for _, d := range a.dests {
		if now.Sub(d.lastActive) <= 5*time.Second {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].down != out[j].down {
			return out[i].down > out[j].down
		}
		if out[i].up != out[j].up {
			return out[i].up > out[j].up
		}
		return out[i].label < out[j].label
	})
	return out
}

type model struct {
	ctx  context.Context
	ch   chan tea.Msg
	w, h int

	apps                 map[string]*app
	totDown, totUp       float64
	locDown              float64
	hist                 []float64
	qual                 float64
	tunnelName           string
	tunnelSeen           time.Time
	idlePings, loadPings []float64
	lastPing             float64
	pingFail             bool

	nqRunning bool
	nq        *nqMsg
	spin      spinner.Model

	filter    textinput.Model
	filtering bool
	cursor    int
	offset    int
	err       string

	tabs     []tabInfo
	ipTab    map[string][]int
	tabErr   string
	expanded map[string]bool
}

// labelFor names a remote IP for an app and finds a matching browser tab title.
func (m model) labelFor(appName, ip string) (string, string) {
	if isPrivateIP(ip) {
		return "LAN", ""
	}
	// exact IP, then IPv6 /64, then Cloudflare per-site hextets
	for _, key := range matchKeys(ip) {
		for _, i := range m.ipTab[key] {
			if m.tabs[i].browser == appName {
				return m.tabs[i].domain, m.tabTitle(appName, m.tabs[i].domain)
			}
		}
	}
	// informative PTR (e.g. googlevideo.com) > known IP range > any PTR > raw IP
	label := ip
	ptr := ""
	if net.ParseIP(ip) == nil {
		ptr = regDomain(ip) // nettop already gave a hostname
	} else if p := rdns.lookup(ip); p != "" {
		ptr = regDomain(p)
	}
	org := orgFor(ip)
	switch {
	case ptr != "" && cdnAlias[ptr] != nil && ptr != "1e100.net":
		label = ptr
	case org != "":
		label = org
	case ptr != "":
		label = ptr
	}
	return label, m.tabTitle(appName, label)
}

func (m model) tabTitle(appName, domain string) string {
	cands := append([]string{domain}, cdnAlias[domain]...)
	first, n := "", 0
	for _, c := range cands {
		for _, t := range m.tabs {
			if t.browser == appName && t.domain == c {
				if n == 0 {
					first = t.title
				}
				n++
			}
		}
		if n > 0 {
			break
		}
	}
	if n > 1 {
		return fmt.Sprintf("%s (+%d tabs)", first, n-1)
	}
	return first
}

func (m model) ordered() (inet, local []*app) {
	now := time.Now()
	flt := strings.ToLower(m.filter.Value())
	for _, a := range m.apps {
		if now.Sub(a.lastActive) > 10*time.Second {
			continue
		}
		if flt != "" && !strings.Contains(strings.ToLower(a.name), flt) {
			match := false
			for _, d := range a.dests {
				if strings.Contains(strings.ToLower(d.label+" "+d.title), flt) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if a.local {
			local = append(local, a)
		} else {
			inet = append(inet, a)
		}
	}
	srt := func(s []*app) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].down != s[j].down {
				return s[i].down > s[j].down
			}
			if s[i].up != s[j].up {
				return s[i].up > s[j].up
			}
			return s[i].name < s[j].name
		})
	}
	srt(inet)
	srt(local)
	return
}

func (m model) selected() *app {
	inet, local := m.ordered()
	all := append(inet, local...)
	if len(all) == 0 {
		return nil
	}
	c := m.cursor
	if c >= len(all) {
		c = len(all) - 1
	}
	return all[c]
}

func newModel(ctx context.Context) model {
	ti := textinput.New()
	ti.Prompt = "/"
	ti.CharLimit = 40
	ti.PromptStyle = sAcc
	ti.TextStyle = sFg
	ti.Cursor.Style = sAcc
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = sAcc
	return model{ctx: ctx, ch: make(chan tea.Msg, 16), apps: map[string]*app{}, filter: ti, spin: s,
		expanded: map[string]bool{}, ipTab: map[string][]int{}}
}

func (m model) Init() tea.Cmd {
	go runNettop(m.ctx, m.ch)
	return tea.Batch(waitMsg(m.ch), doPing(m.ctx), pingTick(), tick(), pollTabs(m.ctx))
}

func pushAvg(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > 5 {
		s = s[len(s)-5:]
	}
	return s
}

func avg(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	t := 0.0
	for _, v := range s {
		t += v
	}
	return t / float64(len(s))
}

func (m *model) applySample(rows []procRow) {
	now := time.Now()
	type dagg struct {
		in, out float64
		title   string
	}
	type agg struct {
		in, out float64
		dests   map[string]*dagg
	}
	g := map[string]*agg{}
	var tD, tU, lD, q float64
	for _, r := range rows {
		q += r.rtx + r.oo
		if isTunnel(r.name) {
			if r.in+r.out > 0 {
				m.tunnelName = r.name
				m.tunnelSeen = now
			}
			continue
		}
		n := groupName(r.name)
		if n == "" {
			continue
		}
		a := g[n]
		if a == nil {
			a = &agg{dests: map[string]*dagg{}}
			g[n] = a
		}
		a.in += r.in * 8
		a.out += r.out * 8
		for _, c := range r.conns {
			label, title := m.labelFor(n, c.ip)
			d := a.dests[label]
			if d == nil {
				d = &dagg{}
				a.dests[label] = d
			}
			d.in += c.in * 8
			d.out += c.out * 8
			if title != "" {
				d.title = title
			}
		}
	}
	for _, a := range m.apps {
		a.down, a.up = 0, 0
		for _, d := range a.dests {
			d.down, d.up = 0, 0
		}
	}
	for n, v := range g {
		a := m.apps[n]
		if a == nil {
			a = &app{name: n, local: isLocal(n), dests: map[string]*dest{}}
			m.apps[n] = a
		}
		a.down, a.up = v.in, v.out
		if v.in+v.out > 0 {
			a.lastActive = now
		}
		for l, dv := range v.dests {
			d := a.dests[l]
			if d == nil {
				d = &dest{label: l}
				a.dests[l] = d
			}
			d.down, d.up, d.lastActive = dv.in, dv.out, now
			if dv.title != "" {
				d.title = dv.title
			}
		}
		for l, d := range a.dests {
			if now.Sub(d.lastActive) > time.Minute {
				delete(a.dests, l)
			}
		}
		if a.local {
			lD += v.in
		} else {
			tD += v.in
			tU += v.out
		}
	}
	m.totDown, m.totUp, m.locDown, m.qual = tD, tU, lD, q
	m.hist = append(m.hist, tD)
	if len(m.hist) > 60 {
		m.hist = m.hist[len(m.hist)-60:]
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case sampleMsg:
		m.applySample(msg.rows)
		return m, waitMsg(m.ch)
	case nettopErrMsg:
		m.err = msg.err.Error()
		return m, nil
	case tickMsg:
		return m, tick()
	case tabsTickMsg:
		return m, pollTabs(m.ctx)
	case tabsMsg:
		m.tabs, m.ipTab, m.tabErr = msg.tabs, msg.ipTab, msg.err
		return m, tabsTick()
	case pingTickMsg:
		return m, tea.Batch(doPing(m.ctx), pingTick())
	case pingMsg:
		m.pingFail = !msg.ok
		if msg.ok {
			m.lastPing = msg.ms
			if m.totDown < 1e6 {
				m.idlePings = pushAvg(m.idlePings, msg.ms)
			} else if m.totDown > 5e6 {
				m.loadPings = pushAvg(m.loadPings, msg.ms)
			}
		}
		return m, nil
	case nqMsg:
		m.nqRunning = false
		r := msg
		m.nq = &r
		return m, nil
	case spinner.TickMsg:
		if !m.nqRunning {
			return m, nil
		}
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c
	case tea.KeyMsg:
		if m.filtering {
			switch msg.String() {
			case "enter":
				m.filtering = false
				m.filter.Blur()
				return m, nil
			case "esc":
				m.filtering = false
				m.filter.Blur()
				m.filter.SetValue("")
				return m, nil
			case "ctrl+c":
				return m, tea.Quit
			}
			var c tea.Cmd
			m.filter, c = m.filter.Update(msg)
			m.cursor, m.offset = 0, 0
			return m, c
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "t":
			if !m.nqRunning {
				m.nqRunning = true
				return m, tea.Batch(runNQ(m.ctx), m.spin.Tick)
			}
		case "/":
			m.filtering = true
			m.filter.Focus()
			return m, textinput.Blink
		case "esc":
			m.filter.SetValue("")
		case "l", "enter", "right", "h", "left":
			if a := m.selected(); a != nil {
				k := msg.String()
				m.expanded[a.name] = k == "l" || k == "right" || (k == "enter" && !m.expanded[a.name])
			}
		case "j", "down":
			m.cursor++
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		}
	}
	return m, nil
}

// ---------- formatting ----------

func fmtRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mb/s", bps/1e6)
	case bps >= 1e4:
		return fmt.Sprintf("%.0f Kb/s", bps/1e3)
	case bps > 0:
		return fmt.Sprintf("%.1f Kb/s", bps/1e3)
	}
	return "0 Kb/s"
}

func padR(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		if n <= 1 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}

func padL(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return strings.Repeat(" ", n-len(r)) + s
}

func sparkline(h []float64, width int) (string, float64) {
	bars := []rune("▁▂▃▄▅▆▇█")
	if width > 60 {
		width = 60
	}
	if len(h) > width {
		h = h[len(h)-width:]
	}
	mx := 0.0
	for _, v := range h {
		if v > mx {
			mx = v
		}
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(h)))
	for _, v := range h {
		i := 0
		if mx > 0 {
			i = int(v / mx * float64(len(bars)-1))
		}
		b.WriteRune(bars[i])
	}
	return b.String(), mx
}

func bar(share float64, n int) string {
	if share < 0 {
		share = 0
	}
	if share > 1 {
		share = 1
	}
	f := int(share*float64(n) + 0.5)
	return sAcc.Render(strings.Repeat("█", f)) + sDim.Render(strings.Repeat("░", n-f))
}

// diagnose: is slowness the user's network or the remote end?
func (m model) diagnose() (string, lipgloss.Style) {
	idle, load := avg(m.idlePings), avg(m.loadPings)
	rough := m.qual > 50
	bloat := idle > 0 && load > 3*idle
	var top *app
	for _, a := range m.apps {
		if !a.local && (top == nil || a.down > top.down) {
			top = a
		}
	}
	if m.pingFail {
		return "your network: ping to 1.1.1.1 failing (no route / packet loss)", sWarn
	}
	if m.totDown < 1e6 {
		if m.nq == nil {
			return "idle — press [t] to measure line capacity", sDim
		}
		return "idle", sDim
	}
	if m.nq != nil && m.nq.err == nil && m.nq.dl > 0 {
		util := m.totDown / m.nq.dl
		if util >= 0.8 {
			return fmt.Sprintf("your network: line saturated (%.0f%% of %s tested)", util*100, fmtRate(m.nq.dl)), sWarn
		}
		if rough || bloat {
			why := "packet loss/reordering"
			if bloat {
				why = "bufferbloat (ping ↑ under load)"
			}
			return fmt.Sprintf("your network: %s at only %.0f%% capacity", why, util*100), sWarn
		}
		if util < 0.5 && top != nil {
			who := top.name
			if ds := top.activeDests(time.Now()); len(ds) > 0 {
				who += " ← " + ds[0].label
				if ds[0].title != "" {
					who += " (" + ds[0].title + ")"
				}
			}
			return fmt.Sprintf("remote/server: line healthy, %.0f%% used — %s limited by destination", util*100, who), sAcc
		}
		return fmt.Sprintf("ok: %.0f%% of line capacity, no loss", util*100), sFg
	}
	if rough || bloat {
		return "your network: loss or bufferbloat under load", sWarn
	}
	return "line looks healthy — slowness likely remote; press [t] to confirm capacity", sDim
}

// ---------- view ----------

func (m model) View() string {
	if m.w == 0 {
		return ""
	}
	w := m.w
	var lines []string
	line := func(parts ...string) { lines = append(lines, strings.Join(parts, "")) }

	// header
	idle, load := avg(m.idlePings), avg(m.loadPings)
	ps := func(v float64) string {
		if v == 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f", v)
	}
	pingPart := sDim.Render("ping ") + sFg.Render(ps(idle)+"/"+ps(load)+"ms")
	if idle > 0 && load > 3*idle {
		pingPart += sp(1) + sWarn.Render("▲")
	}
	lq := sFg.Render("line: ok")
	if m.qual > 50 {
		lq = sWarn.Render("line: rough")
	}
	line(sAccB.Render(" checkyospeed"), sp(3),
		sBold.Render("↓ "+fmtRate(m.totDown)), sp(2),
		sBold.Render("↑ "+fmtRate(m.totUp)), sp(3), pingPart, sp(3), lq)

	switch {
	case m.nqRunning:
		line(sp(1), m.spin.View(), sDim.Render(" running networkQuality…"))
	case m.nq != nil && m.nq.err != nil:
		line(sWarn.Render(" test failed: " + m.nq.err.Error()))
	case m.nq != nil:
		line(sDim.Render(" test "+m.nq.at.Format("15:04")+"  "),
			sFg.Render("↓ "+fmtRate(m.nq.dl)+"  ↑ "+fmtRate(m.nq.ul)),
			sDim.Render(fmt.Sprintf("  rpm %.0f", m.nq.rpm)))
	default:
		line(sDim.Render(" no speed test yet"))
	}
	d, ds := m.diagnose()
	line(sDim.Render(" diag "), ds.Render(padR(d, max(w-7, 1))))

	sl, mx := sparkline(m.hist, max(w-20, 10))
	line(sp(1), sAcc.Render(sl), sDim.Render(" peak "+fmtRate(mx)))

	// table geometry
	const cD, cU, cB = 11, 11, 16
	nameW := w - (2 + cD + 2 + cU + 2 + cB + 2)
	if nameW > 32 {
		nameW = 32
	}
	if nameW < 6 {
		nameW = 6
	}
	line(sDim.Render("  " + padR("APP", nameW) + " " + padL("↓", cD) + "  " + padL("↑", cU) + "  " + padR("share", cB)))
	line(sDim.Render(" " + strings.Repeat("─", max(min(w-2, nameW+cD+cU+cB+8), 1))))

	// rows
	now := time.Now()
	inet, local := m.ordered()
	titleW := w - (2 + nameW + 1 + cD + 2 + cU + 2) - 1

	type rl struct {
		text string
		sel  int // -1 = separator
	}
	var body []rl
	cur := m.cursor
	nSel := len(inet) + len(local)
	if cur >= nSel {
		cur = max(nSel-1, 0)
	}
	k := 0
	render := func(a *app, tot float64) string {
		mark, ns := "  ", sFg
		if k == cur {
			mark, ns = "▌ ", sSel
		}
		ds := sFg
		if a.down == 0 {
			ds = sDim
		}
		share := 0.0
		if tot > 0 {
			share = a.down / tot
		}
		return sAcc.Render(mark) + ns.Render(padR(a.name, nameW)) + sp(1) +
			ds.Render(padL(fmtRate(a.down), cD)) + sp(2) +
			sDim.Render(padL(fmtRate(a.up), cU)) + sp(2) + bar(share, cB)
	}
	tree := func(a *app) {
		ds := a.activeDests(now)
		limit := 3
		if m.expanded[a.name] {
			limit = len(ds)
		}
		more := 0
		if len(ds) > limit {
			more = len(ds) - limit
			ds = ds[:limit]
		}
		for i, d := range ds {
			conn := "├ "
			if i == len(ds)-1 && more == 0 {
				conn = "└ "
			}
			rs := sFg
			if d.down == 0 {
				rs = sDim
			}
			t := ""
			if d.title != "" && titleW > 4 {
				t = sAcc.Render(padR("▸ "+d.title, titleW))
			}
			body = append(body, rl{sp(2) + sDim.Render(conn) + rs.Render(padR(d.label, nameW-2)) + sp(1) +
				rs.Render(padL(fmtRate(d.down), cD)) + sp(2) + sDim.Render(padL(fmtRate(d.up), cU)) + sp(2) + t, -1})
		}
		if more > 0 {
			body = append(body, rl{sp(2) + sDim.Render(fmt.Sprintf("└ +%d more  [l] expand", more)), -1})
		}
	}
	for _, a := range inet {
		body = append(body, rl{render(a, m.totDown), k})
		k++
		tree(a)
	}
	if len(local) > 0 {
		body = append(body, rl{sDim.Render(" ── local ──"), -1})
		for _, a := range local {
			body = append(body, rl{render(a, m.locDown), k})
			k++
			tree(a)
		}
	}

	footerLines := 1
	avail := m.h - len(lines) - footerLines
	if avail < 1 {
		avail = 1
	}
	curLine := 0
	for i, r := range body {
		if r.sel == cur {
			curLine = i
		}
	}
	off := m.offset
	if curLine < off {
		off = curLine
	}
	if curLine >= off+avail {
		off = curLine - avail + 1
	}
	if off > max(len(body)-avail, 0) {
		off = max(len(body)-avail, 0)
	}
	shown := 0
	for i := off; i < len(body) && shown < avail; i++ {
		lines = append(lines, body[i].text)
		shown++
	}
	for ; shown < avail; shown++ {
		lines = append(lines, "")
	}

	// footer
	var f string
	if m.filtering {
		f = sp(1) + m.filter.View() + sDim.Render("  enter apply · esc clear")
	} else {
		f = sDim.Render(" [t] test [/] filter [j/k] move [l/h] expand [q] quit")
		if v := m.filter.Value(); v != "" {
			f += sAcc.Render("  filter: " + v)
		}
	}
	if m.tunnelName != "" && now.Sub(m.tunnelSeen) < 10*time.Second {
		lbl := "via VPN"
		if strings.Contains(strings.ToLower(m.tunnelName), "warp") {
			lbl = "via WARP"
		}
		f += sp(3) + sAcc.Render(lbl)
	}
	if m.tabErr != "" {
		f += sp(3) + sWarn.Render("tabs: "+m.tabErr)
	}
	if m.err != "" {
		f += sp(3) + sWarn.Render(m.err)
	}
	lines = append(lines, f)

	out := make([]string, len(lines))
	full := base.Width(w)
	for i, l := range lines {
		out[i] = full.Render(l)
	}
	return base.Width(w).Height(m.h).MaxHeight(m.h).Render(strings.Join(out, "\n"))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := tea.NewProgram(newModel(ctx), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		cancel()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
