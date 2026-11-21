package httpapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"awg-panel/internal/auth"
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/service"
	"awg-panel/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

type session struct {
	AccountID string
	Role      string
	Login     string
	CSRF      string
	Expires   time.Time
	Secure    bool
}
type bucket struct {
	Tokens float64
	Last   time.Time
}
type API struct {
	transfers   map[string]importTicket
	challenges  map[string]loginChallenge
	enrollments map[string]enrollment
	dummyHash   string
	configMu    sync.RWMutex
	service     *service.Service
	config      config.Config
	root        *os.Root
	mu          sync.Mutex
	sessions    map[string]session
	limits      map[string]bucket
	global      bucket
	loginGate   chan struct{}
	origins     map[string]bool
}

func New(s *service.Service) (*API, error) {
	r, err := os.OpenRoot(s.Config.WebDir)
	if err != nil {
		return nil, err
	}
	a := &API{transfers: map[string]importTicket{}, service: s, config: s.Config, root: r, sessions: map[string]session{}, challenges: map[string]loginChallenge{}, enrollments: map[string]enrollment{}, limits: map[string]bucket{}, loginGate: make(chan struct{}, 1), origins: map[string]bool{}}
	a.config.Password = ""
	if s.Store == nil {
		r.Close()
		return nil, fmt.Errorf("account store is required")
	}
	account, err := s.Store.Account(model.BootstrapAccountID)
	if err != nil || !account.Enabled || account.Role != "superadmin" {
		r.Close()
		return nil, fmt.Errorf("initial superadministrator account is unavailable")
	}
	if err = s.Store.ConfigureMFAKey(s.Config.TOTPKeyFile); err != nil {
		r.Close()
		return nil, err
	}
	a.dummyHash = account.PasswordHash
	a.setOrigins()
	return a, nil
}
func (a *API) setOrigins() {
	a.origins = map[string]bool{}
	for _, host := range []string{"10.8.0.1", a.config.Host} {
		a.origins["http://"+net.JoinHostPort(host, strconv.Itoa(a.config.PanelPort))] = true
	}
	if a.service.Network.IPv6 {
		a.origins["http://"+net.JoinHostPort("fd42:8::1", strconv.Itoa(a.config.PanelPort))] = true
	}
	if a.config.PublicOrigin != "" {
		a.origins[a.config.PublicOrigin] = true
	}
	if a.config.ExternalBind != "" {
		_, p, _ := net.SplitHostPort(a.config.ExternalBind)
		a.origins["http://"+net.JoinHostPort(a.config.Host, p)] = true
		a.origins["http://127.0.0.1:"+p] = true
		a.origins["http://localhost:"+p] = true
	}
	normalized := make(map[string]bool, len(a.origins))
	for origin := range a.origins {
		normalized[normalizeOrigin(origin)] = true
	}
	a.origins = normalized
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
	return decodeLimit(w, r, v, 8192)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		problem(w, 415, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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
	if strings.HasPrefix(r.URL.Path, "/api/transfer") || (strings.HasPrefix(r.URL.Path, "/api/account/") && r.Method != "GET" && r.Method != "HEAD") || (r.URL.Path == "/api/addresses" && r.Method == "PUT") || ((r.URL.Path == "/api/accounts" || strings.HasPrefix(r.URL.Path, "/api/accounts/")) && r.Method != "GET" && r.Method != "HEAD") {
		a.configMu.Lock()
		defer a.configMu.Unlock()
	} else {
		a.configMu.RLock()
		defer a.configMu.RUnlock()
	}
	if a.secure(r) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
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
	if r.URL.Path == "/api/login/verify" && r.Method == "POST" {
		a.verifyLogin(w, r)
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
	if sess.Role != "superadmin" {
		switch r.URL.Path {
		case "/api/settings", "/api/addresses", "/api/key-policy", "/api/keys/stored", "/api/audit":
			problem(w, 403, "Superadministrator access required")
			return
		}
	}
	switch {
	case r.URL.Path == "/api/transfer" || strings.HasPrefix(r.URL.Path, "/api/transfer/"):
		a.transfer(w, r, sess)
	case r.URL.Path == "/api/account/sessions" && r.Method == "DELETE":
		a.revokeSessions(w, r, sess, sess.AccountID)
	case r.URL.Path == "/api/account/totp" || strings.HasPrefix(r.URL.Path, "/api/account/totp/"):
		a.mfa(w, r, sess)
	case r.URL.Path == "/api/accounts" || strings.HasPrefix(r.URL.Path, "/api/accounts/"):
		a.accounts(w, r, sess)
	case r.URL.Path == "/api/audit" && r.Method == "GET":
		entries, err := a.service.Store.Audit()
		if err != nil {
			problem(w, 500, "Audit could not be read")
			return
		}
		jsonReply(w, 200, entries)
	case r.URL.Path == "/api/key-policy":
		a.keyPolicy(w, r)
	case r.URL.Path == "/api/keys/stored" && r.Method == "DELETE":
		a.purgeKeys(w, r)
	case r.URL.Path == "/api/addresses" && r.Method == "GET":
		jsonReply(w, 200, a.service.Addresses())
	case r.URL.Path == "/api/addresses" && r.Method == "PUT":
		a.changeAddresses(w, r)
	case r.URL.Path == "/api/account/password" && r.Method == "PUT":
		a.changePassword(w, r)
	case r.URL.Path == "/api/settings" && r.Method == "GET":
		jsonReply(w, 200, a.service.Settings())
	case r.URL.Path == "/api/settings" && r.Method == "PUT":
		var next model.Settings
		if !decode(w, r, &next) {
			return
		}
		if err := next.Validate(); err != nil {
			problem(w, 400, err.Error())
			return
		}
		result, err := a.service.UpdateSettings(next)
		if errors.Is(err, store.ErrSettingsConflict) {
			problem(w, 409, err.Error())
			return
		}
		if err != nil {
			problem(w, 500, "Settings could not be saved; reload and try again")
			return
		}
		jsonReply(w, 200, result)
	case r.URL.Path == "/api/session" && r.Method == "GET":
		jsonReply(w, 200, map[string]any{"accountId": sess.AccountID, "login": sess.Login, "role": sess.Role, "csrf": sess.CSRF, "ipv6": a.service.Network.IPv6, "endpoint": net.JoinHostPort(a.config.Host, strconv.Itoa(a.config.Port)), "serverName": a.service.Settings().ServerName})
	case r.URL.Path == "/api/logout" && r.Method == "POST":
		c, _ := r.Cookie("awg_session")
		a.mu.Lock()
		delete(a.sessions, c.Value)
		delete(a.transfers, c.Value)
		delete(a.enrollments, c.Value)
		a.mu.Unlock()
		a.cookie(w, r, "", -1)
		jsonReply(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/api/peers" && r.Method == "GET":
		list, err := a.service.ListFor(sess.AccountID)
		if err != nil {
			problem(w, 500, "Devices could not be read")
			return
		}
		jsonReply(w, 200, list)
	case r.URL.Path == "/api/peers" && r.Method == "POST":
		var v struct {
			OwnerID string `json:"ownerId"`
			Name    string `json:"name"`
			Group   string `json:"group"`
		}
		if !decode(w, r, &v) {
			return
		}
		issued, err := a.service.IssueFor(r.Context(), sess.AccountID, v.OwnerID, "", v.Name, v.Group, "")
		if err != nil {
			problem(w, 400, err.Error())
			return
		}
		issuanceReply(w, 201, issued)
	case strings.HasPrefix(r.URL.Path, "/api/peers/"):
		a.peer(w, r, sess)
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
	account, err := a.service.Store.Account(s.AccountID)
	if err != nil || !account.Active {
		delete(a.sessions, c.Value)
		return session{}, false
	}
	s.Role = account.Role
	s.Login = account.Login
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
		Login    string `json:"login"`
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
	if v.Login == "" {
		v.Login = "admin"
	}
	account, err := a.service.Store.AccountByLogin(v.Login)
	hash := account.PasswordHash
	if err != nil {
		hash = a.dummyHash
	}
	valid := auth.VerifyPassword(hash, v.Password)
	if !valid || err != nil || !account.Active {
		problem(w, 401, "Invalid login or password")
		return
	}
	status, err := a.service.Store.MFAStatus(account.ID)
	if err != nil {
		problem(w, 500, "Authentication unavailable")
		return
	}
	if status.Enabled {
		a.beginChallenge(w, r, account)
		return
	}
	a.newSession(w, r, account.ID)
}
func (a *API) newSession(w http.ResponseWriter, r *http.Request, accountID string) {
	token := model.Random(32)
	s := session{AccountID: accountID, CSRF: model.Random(32), Expires: time.Now().Add(12 * time.Hour), Secure: a.secure(r)}
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
		delete(a.enrollments, old.Value)
	}
	if old, e := r.Cookie("awg_challenge"); e == nil {
		delete(a.challenges, old.Value)
	}
	a.sessions[token] = s
	a.mu.Unlock()
	a.cookie(w, r, token, 12*3600)
	jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
}
func (a *API) peer(w http.ResponseWriter, r *http.Request, sess session) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/peers/"), "/")
	id := parts[0]
	if id == "" || !a.service.CanAccessDevice(sess.AccountID, id) {
		problem(w, 404, "Device not found")
		return
	}
	if len(parts) == 1 {
		if r.Method == "DELETE" {
			if err := a.service.ChangeFor(r.Context(), sess.AccountID, id, "", "", nil, true); err != nil {
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
			if err := a.service.ChangeFor(r.Context(), sess.AccountID, id, v.Name, v.Group, v.Enabled, false); err != nil {
				problem(w, 400, err.Error())
				return
			}
			jsonReply(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	if len(parts) == 2 && parts[1] == "reissue" && r.Method == "POST" {
		a.reissue(w, r, id, sess.AccountID)
		return
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
	snapshot, err := a.service.ExportSnapshot(id)
	if err != nil {
		problem(w, 404, err.Error())
		return
	}
	if version := r.URL.Query().Get("version"); version != "" && version != snapshot.Version {
		problem(w, 409, "Configuration changed; close and reopen Connect to export the current profile")
		return
	}
	value := snapshot.Link
	if kind == "config" {
		value = snapshot.Config
	}
	switch kind {
	case "config":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="awg-%s.conf"`, id))
		_, _ = io.WriteString(w, value)
	case "link":
		// A profile too large for QR must still offer the clipboard link.
		chunks, _ := artifact.QRChunks(value)
		jsonReply(w, 200, map[string]any{"link": value, "qrParts": len(chunks), "version": snapshot.Version})
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
	files := map[string]string{"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css", "/logo.svg": "logo.svg", "/favicon.svg": "favicon.svg"}
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
	case "logo.svg", "favicon.svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case "styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	http.ServeContent(w, r, name, info.ModTime(), bytes.NewReader(b))
}
