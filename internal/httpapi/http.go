package httpapi

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"awg-panel/internal/artifact"
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/service"
	qrcode "github.com/skip2/go-qrcode"
)

type session struct {
	CSRF    string
	Expires time.Time
	Secure  bool
}
type bucket struct {
	Tokens float64
	Last   time.Time
}
type API struct {
	service        *service.Service
	config         config.Config
	root           *os.Root
	mu             sync.Mutex
	sessions       map[string]session
	limits         map[string]bucket
	global         bucket
	salt, password []byte
	loginGate      chan struct{}
	origins        map[string]bool
}

func New(s *service.Service) (*API, error) {
	r, err := os.OpenRoot(s.Config.WebDir)
	if err != nil {
		return nil, err
	}
	a := &API{service: s, config: s.Config, root: r, sessions: map[string]session{}, limits: map[string]bucket{}, salt: []byte(model.Random(32)), loginGate: make(chan struct{}, 1), origins: map[string]bool{}}
	a.password, err = pbkdf2.Key(sha256.New, s.Config.Password, a.salt, 210000, 32)
	a.config.Password = ""
	if err != nil {
		r.Close()
		return nil, err
	}
	for _, host := range []string{"10.8.0.1", s.Config.Host} {
		a.origins["http://"+net.JoinHostPort(host, strconv.Itoa(s.Config.PanelPort))] = true
	}
	if s.Network.IPv6 {
		a.origins["http://"+net.JoinHostPort("fd42:8::1", strconv.Itoa(s.Config.PanelPort))] = true
	}
	if s.Config.PublicOrigin != "" {
		a.origins[s.Config.PublicOrigin] = true
	}
	if s.Config.ExternalBind != "" {
		_, p, _ := net.SplitHostPort(s.Config.ExternalBind)
		a.origins["http://"+net.JoinHostPort(s.Config.Host, p)] = true
		a.origins["http://127.0.0.1:"+p] = true
		a.origins["http://localhost:"+p] = true
	}
	normalized := make(map[string]bool, len(a.origins))
	for origin := range a.origins {
		normalized[normalizeOrigin(origin)] = true
	}
	a.origins = normalized
	return a, nil
}
func normalizeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	host := strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return u.Scheme + "://" + host
}
func (a *API) Close() error { return a.root.Close() }
func peerIP(r *http.Request) netip.Addr {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip, _ := netip.ParseAddr(h)
	return ip.Unmap()
}
func (a *API) trusted(ip netip.Addr) bool {
	for _, p := range a.config.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *API) requestIP(r *http.Request) netip.Addr {
	ip := peerIP(r)
	if !a.trusted(ip) {
		return ip
	}
	// Walk right-to-left, stopping at the first untrusted hop. Never trust arbitrary XFF.
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		next, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		ip = next.Unmap()
		if !a.trusted(ip) {
			return ip
		}
	}
	return ip
}
func (a *API) secure(r *http.Request) bool {
	return r.TLS != nil || (a.trusted(peerIP(r)) && r.Header.Get("X-Forwarded-Proto") == "https")
}
func jsonReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		problem(w, 415, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem(w, 400, "Invalid JSON request")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		problem(w, 400, "Only one JSON object is allowed")
		return false
	}
	return true
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	ip := peerIP(r)
	claimed := a.requestIP(r)
	if (model.IsVPN(ip) && !a.service.Home(ip)) || (model.IsVPN(claimed) && !a.service.Home(claimed)) || (!model.IsVPN(ip) && a.config.ExternalBind == "") {
		problem(w, 403, "Panel access is restricted to home devices")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		a.static(w, r)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		origin := normalizeOrigin(r.Header.Get("Origin"))
		if origin == "" || !a.origins[origin] || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			problem(w, 403, "Request origin is not allowed")
			return
		}
	}
	if r.URL.Path == "/api/login" && r.Method == "POST" {
		a.login(w, r)
		return
	}
	sess, ok := a.current(r)
	if !ok {
		problem(w, 401, "Authentication required")
		return
	}
	if sess.Secure && !a.secure(r) {
		problem(w, 403, "HTTPS is required for this session")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
		problem(w, 403, "Invalid CSRF token")
		return
	}
	switch {
	case r.URL.Path == "/api/session" && r.Method == "GET":
		jsonReply(w, 200, map[string]any{"csrf": sess.CSRF, "ipv6": a.service.Network.IPv6, "endpoint": net.JoinHostPort(a.config.Host, strconv.Itoa(a.config.Port))})
	case r.URL.Path == "/api/logout" && r.Method == "POST":
		c, _ := r.Cookie("awg_session")
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
		a.cookie(w, r, "", -1)
		jsonReply(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/api/peers" && r.Method == "GET":
		jsonReply(w, 200, a.service.List())
	case r.URL.Path == "/api/peers" && r.Method == "POST":
		var v struct {
			Name  string `json:"name"`
			Group string `json:"group"`
		}
		if !decode(w, r, &v) {
			return
		}
		if err := a.service.Change(r.Context(), "", v.Name, v.Group, nil, false); err != nil {
			problem(w, 400, err.Error())
			return
		}
		jsonReply(w, 201, map[string]bool{"ok": true})
	case strings.HasPrefix(r.URL.Path, "/api/peers/"):
		a.peer(w, r)
	default:
		problem(w, 404, "Endpoint not found")
	}
}
func (a *API) cookie(w http.ResponseWriter, r *http.Request, token string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.secure(r), MaxAge: age})
}
func (a *API) current(r *http.Request) (session, bool) {
	c, err := r.Cookie("awg_session")
	if err != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, c.Value)
		return session{}, false
	}
	return s, true
}
func refill(b bucket, now time.Time, capacity, perSecond float64) bucket {
	if b.Last.IsZero() {
		b.Tokens = capacity
	} else {
		b.Tokens += now.Sub(b.Last).Seconds() * perSecond
		if b.Tokens > capacity {
			b.Tokens = capacity
		}
	}
	b.Last = now
	return b
}
func (a *API) allowed(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.limits) >= 4096 {
		for k, b := range a.limits {
			if now.Sub(b.Last) > 10*time.Minute {
				delete(a.limits, k)
			}
		}
		if _, exists := a.limits[ip]; !exists && len(a.limits) >= 4096 {
			return false
		}
	}
	b := refill(a.limits[ip], now, 5, 1.0/30)
	a.global = refill(a.global, now, 10, 1)
	ok := b.Tokens >= 1 && a.global.Tokens >= 1
	if ok {
		b.Tokens--
		a.global.Tokens--
	}
	a.limits[ip] = b
	return ok
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many login attempts; try again later")
		return
	}
	var v struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Password) > 256 {
		problem(w, 401, "Invalid password")
		return
	}
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		problem(w, 429, "Login is busy; try again shortly")
		return
	}
	hash, err := pbkdf2.Key(sha256.New, v.Password, a.salt, 210000, 32)
	if err != nil || subtle.ConstantTimeCompare(hash, a.password) != 1 {
		problem(w, 401, "Invalid password")
		return
	}
	token := model.Random(32)
	s := session{CSRF: model.Random(32), Expires: time.Now().Add(12 * time.Hour), Secure: a.secure(r)}
	a.mu.Lock()
	for k, old := range a.sessions {
		if time.Now().After(old.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 128 {
		a.mu.Unlock()
		problem(w, 429, "Too many active sessions")
		return
	}
	if old, e := r.Cookie("awg_session"); e == nil {
		delete(a.sessions, old.Value)
	}
	a.sessions[token] = s
	a.mu.Unlock()
	a.cookie(w, r, token, 12*3600)
	jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
}
func (a *API) peer(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/peers/"), "/")
	id := parts[0]
	if id == "" {
		problem(w, 404, "Device not found")
		return
	}
	if len(parts) == 1 {
		if r.Method == "DELETE" {
			if err := a.service.Change(r.Context(), id, "", "", nil, true); err != nil {
				problem(w, 400, err.Error())
				return
			}
			jsonReply(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.Method == "PATCH" {
			var v struct {
				Name    string `json:"name"`
				Group   string `json:"group"`
				Enabled *bool  `json:"enabled"`
			}
			if !decode(w, r, &v) {
				return
			}
			if err := a.service.Change(r.Context(), id, v.Name, v.Group, v.Enabled, false); err != nil {
				problem(w, 400, err.Error())
				return
			}
			jsonReply(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	if len(parts) != 2 || r.Method != "GET" {
		problem(w, 404, "Endpoint not found")
		return
	}
	kind := parts[1]
	if kind != "config" && kind != "link" && kind != "qr" {
		problem(w, 404, "Export not found")
		return
	}
	value, err := a.service.Export(id, kind != "config")
	if err != nil {
		problem(w, 404, err.Error())
		return
	}
	switch kind {
	case "config":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="awg-%s.conf"`, id))
		_, _ = io.WriteString(w, value)
	case "link":
		// A profile too large for QR must still offer the clipboard link.
		chunks, _ := artifact.QRChunks(value)
		jsonReply(w, 200, map[string]any{"link": value, "qrParts": len(chunks)})
	case "qr":
		chunks, err := artifact.QRChunks(value)
		if err != nil {
			problem(w, 422, "QR is unavailable for this profile")
			return
		}
		part := 0
		if raw := r.URL.Query().Get("part"); raw != "" {
			part, err = strconv.Atoi(raw)
		}
		if err != nil || part < 0 || part >= len(chunks) {
			problem(w, 400, "Invalid QR part")
			return
		}
		png, err := qrcode.Encode(chunks[part], qrcode.Low, 768)
		if err != nil {
			problem(w, 422, "This profile is too large for a QR code; use the link or configuration file")
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}
}
func (a *API) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		problem(w, 405, "Method not allowed")
		return
	}
	files := map[string]string{"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css"}
	name, ok := files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := a.root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		http.NotFound(w, r)
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil {
		problem(w, 500, "Cannot read web asset")
		return
	}
	h := sha256.Sum256(b)
	w.Header().Set("ETag", `"`+hex.EncodeToString(h[:])+`"`)
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	}
	switch name {
	case "index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case "app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case "styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	http.ServeContent(w, r, name, info.ModTime(), bytes.NewReader(b))
}
