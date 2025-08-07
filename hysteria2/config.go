package hysteria2

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/thebytearray/libHysteria2/controller"
	"github.com/thebytearray/libHysteria2/nodep"
	"github.com/thebytearray/libHysteria2/proxymux"
	"go.uber.org/zap"
)

type adaptiveConnFactory struct {
	NewFunc    func(addr net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	if f.Obfuscator == nil {
		return f.NewFunc(addr)
	} else {
		conn, err := f.NewFunc(addr)
		if err != nil {
			return nil, err
		}
		return obfs.WrapPacketConn(conn, f.Obfuscator), nil
	}
}

type clientConfig struct {
	Server        string                `mapstructure:"server"`
	Auth          string                `mapstructure:"auth"`
	Transport     clientConfigTransport `mapstructure:"transport"`
	Obfs          clientConfigObfs      `mapstructure:"obfs"`
	TLS           clientConfigTLS       `mapstructure:"tls"`
	QUIC          clientConfigQUIC      `mapstructure:"quic"`
	Bandwidth     clientConfigBandwidth `mapstructure:"bandwidth"`
	FastOpen      bool                  `mapstructure:"fastOpen"`
	Lazy          bool                  `mapstructure:"lazy"`
	SOCKS5        *socks5Config         `mapstructure:"socks5"`
	HTTP          *httpConfig           `mapstructure:"http"`
	TCPForwarding []tcpForwardingEntry  `mapstructure:"tcpForwarding"`
	UDPForwarding []udpForwardingEntry  `mapstructure:"udpForwarding"`
	TCPTProxy     *tcpTProxyConfig      `mapstructure:"tcpTProxy"`
	UDPTProxy     *udpTProxyConfig      `mapstructure:"udpTProxy"`
	TCPRedirect   *tcpRedirectConfig    `mapstructure:"tcpRedirect"`
	TUN           *tunConfig            `mapstructure:"tun"`
}

type clientConfigTransportUDP struct {
	HopInterval time.Duration `mapstructure:"hopInterval"`
}

type clientConfigTransport struct {
	Type string                   `mapstructure:"type"`
	UDP  clientConfigTransportUDP `mapstructure:"udp"`
}

type clientConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type clientConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander clientConfigObfsSalamander `mapstructure:"salamander"`
}

type clientConfigTLS struct {
	SNI       string `mapstructure:"sni"`
	Insecure  bool   `mapstructure:"insecure"`
	PinSHA256 string `mapstructure:"pinSHA256"`
	CA        string `mapstructure:"ca"`
}

type clientConfigQUIC struct {
	InitStreamReceiveWindow     uint64                   `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64                   `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64                   `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64                   `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration            `mapstructure:"maxIdleTimeout"`
	KeepAlivePeriod             time.Duration            `mapstructure:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool                     `mapstructure:"disablePathMTUDiscovery"`
	Sockopts                    clientConfigQUICSockopts `mapstructure:"sockopts"`
}

type clientConfigQUICSockopts struct {
	BindInterface       *string `mapstructure:"bindInterface"`
	FirewallMark        *uint32 `mapstructure:"fwmark"`
	FdControlUnixSocket *string `mapstructure:"fdControlUnixSocket"`
}

type clientConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
}

type socks5Config struct {
	Listen     string `mapstructure:"listen"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	DisableUDP bool   `mapstructure:"disableUDP"`
}

type httpConfig struct {
	Listen   string `mapstructure:"listen"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Realm    string `mapstructure:"realm"`
}

type tcpForwardingEntry struct {
	Listen string `mapstructure:"listen"`
	Remote string `mapstructure:"remote"`
}

type udpForwardingEntry struct {
	Listen  string        `mapstructure:"listen"`
	Remote  string        `mapstructure:"remote"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpTProxyConfig struct {
	Listen string `mapstructure:"listen"`
}

type udpTProxyConfig struct {
	Listen  string        `mapstructure:"listen"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpRedirectConfig struct {
	Listen string `mapstructure:"listen"`
}

type tunConfig struct {
	Name    string        `mapstructure:"name"`
	MTU     uint32        `mapstructure:"mtu"`
	Timeout time.Duration `mapstructure:"timeout"`
	Address struct {
		IPv4 string `mapstructure:"ipv4"`
		IPv6 string `mapstructure:"ipv6"`
	} `mapstructure:"address"`
	Route *struct {
		Strict      bool     `mapstructure:"strict"`
		IPv4        []string `mapstructure:"ipv4"`
		IPv6        []string `mapstructure:"ipv6"`
		IPv4Exclude []string `mapstructure:"ipv4Exclude"`
		IPv6Exclude []string `mapstructure:"ipv6Exclude"`
	} `mapstructure:"route"`
}

type clientModeRunner struct {
	ModeMap map[string]func() error
}

type clientModeRunnerResult struct {
	OK  bool
	Msg string
	Err error
}

func (r *clientModeRunner) Add(name string, f func() error) {
	if r.ModeMap == nil {
		r.ModeMap = make(map[string]func() error)
	}
	r.ModeMap[name] = f
}

func clientSOCKS5(config socks5Config, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}

	if logger != nil {
		logger.Info("Creating SOCKS5 listener", zap.String("addr", config.Listen))
	}

	l, err := proxymux.ListenSOCKS(config.Listen)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to create SOCKS5 listener", zap.Error(err))
		}
		return configError{Field: "listen", Err: err}
	}

	if logger != nil {
		logger.Info("SOCKS5 listener created successfully")
	}

	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	s := Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		DisableUDP:  config.DisableUDP,
		EventLogger: &socks5Logger{},
	}

	if logger != nil {
		logger.Info("SOCKS5 server listening", zap.String("addr", config.Listen))
		logger.Info("Starting SOCKS5 server...")
	}

	err = s.Serve(l)

	if logger != nil {
		logger.Error("SOCKS5 server stopped", zap.Error(err))
	}

	return err
}

type socks5Logger struct{}

func (l *socks5Logger) TCPRequest(addr net.Addr, reqAddr string) {
	logger.Debug("SOCKS5 TCP request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *socks5Logger) TCPError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("SOCKS5 TCP closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("SOCKS5 TCP error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *socks5Logger) UDPRequest(addr net.Addr) {
	logger.Debug("SOCKS5 UDP request", zap.String("addr", addr.String()))
}

func (l *socks5Logger) UDPError(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("SOCKS5 UDP closed", zap.String("addr", addr.String()))
	} else {
		logger.Warn("SOCKS5 UDP error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

func (r *clientModeRunner) Run() clientModeRunnerResult {
	if len(r.ModeMap) == 0 {
		return clientModeRunnerResult{OK: false, Msg: "no mode specified"}
	}

	type modeError struct {
		Name string
		Err  error
	}
	errChan := make(chan modeError, len(r.ModeMap))
	for name, f := range r.ModeMap {
		go func(name string, f func() error) {
			err := f()
			errChan <- modeError{name, err}
		}(name, f)
	}

	// Wait for any one of the modes to fail
	// Modes should run indefinitely unless there's an error
	e := <-errChan
	if e.Err != nil {
		return clientModeRunnerResult{OK: false, Msg: "failed to run " + e.Name, Err: e.Err}
	}

	// If a mode completed without error, it's unexpected for server modes
	return clientModeRunnerResult{OK: true, Msg: e.Name + " completed unexpectedly"}
}

// parseURI tries to parse the server address field as a URI,
// and fills the config with the information contained in the URI.
// Returns whether the server address field is a valid URI.
// This allows a user to use put a URI as the server address and
// omit the fields that are already contained in the URI.
func (c *clientConfig) parseURI() bool {
	u, err := url.Parse(c.Server)
	if err != nil {
		return false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return false
	}
	if u.User != nil {
		auth, err := url.QueryUnescape(u.User.String())
		if err != nil {
			return false
		}
		c.Auth = auth
	}
	c.Server = u.Host
	q := u.Query()
	if obfsType := q.Get("obfs"); obfsType != "" {
		c.Obfs.Type = obfsType
		switch strings.ToLower(obfsType) {
		case "salamander":
			c.Obfs.Salamander.Password = q.Get("obfs-password")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		c.TLS.SNI = sni
	}
	if insecure, err := strconv.ParseBool(q.Get("insecure")); err == nil {
		c.TLS.Insecure = insecure
	}
	if pinSHA256 := q.Get("pinSHA256"); pinSHA256 != "" {
		c.TLS.PinSHA256 = pinSHA256
	}
	return true
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	if c.Server == "" {
		return configError{Field: "server", Err: errors.New("server address is empty")}
	}
	var addr net.Addr
	var err error
	host, port, hostPort := parseServerAddrString(c.Server)
	if !isPortHoppingPort(port) {
		addr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		addr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = addr
	// Special handling for SNI
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	}
	return nil
}

// fillConnFactory must be called after fillServerAddr, as we have different logic
// for ConnFactory depending on whether we have a port hopping address.
func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	so := &controller.SocketOptions{
		BindInterface:       c.QUIC.Sockopts.BindInterface,
		FirewallMark:        c.QUIC.Sockopts.FirewallMark,
		FdControlUnixSocket: c.QUIC.Sockopts.FdControlUnixSocket,
	}
	if err := so.CheckSupported(); err != nil {
		var unsupportedErr *controller.UnsupportedError
		if errors.As(err, &unsupportedErr) {
			return configError{
				Field: "quic.sockopts." + unsupportedErr.Field,
				Err:   errors.New("unsupported on this platform"),
			}
		}
		return configError{Field: "quic.sockopts", Err: err}
	}
	// Inner PacketConn
	var newFunc func(addr net.Addr) (net.PacketConn, error)
	switch strings.ToLower(c.Transport.Type) {
	case "", "udp":
		if hyConfig.ServerAddr.Network() == "udphop" {
			hopAddr := hyConfig.ServerAddr.(*udphop.UDPHopAddr)
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return udphop.NewUDPHopPacketConn(hopAddr, c.Transport.UDP.HopInterval, so.ListenUDP)
			}
		} else {
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return so.ListenUDP()
			}
		}
	default:
		return configError{Field: "transport.type", Err: errors.New("unsupported transport type")}
	}
	// Obfuscation
	var ob obfs.Obfuscator
	var err error
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		// Keep it nil
	case "salamander":
		ob, err = obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return configError{Field: "obfs.salamander.password", Err: err}
		}
	default:
		return configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
	hyConfig.ConnFactory = &adaptiveConnFactory{
		NewFunc:    newFunc,
		Obfuscator: ob,
	}
	return nil
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	hyConfig.Auth = c.Auth
	return nil
}

// normalizeCertHash normalizes a certificate hash string.
// It converts all characters to lowercase and removes possible separators such as ":" and "-".
func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if c.TLS.SNI != "" {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		hyConfig.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return configError{Field: "tls.ca", Err: err}
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	// New core now allows users to omit bandwidth values and use built-in congestion control
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = nodep.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = nodep.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

func (c *clientConfig) Config() (*client.Config, error) {
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	return hyConfig, nil
}

type configError struct {
	Field string
	Err   error
}

func (e configError) Error() string {
	return "invalid config: " + e.Field + ": " + e.Err.Error()
}

func (e configError) Unwrap() error {
	return e.Err
}
