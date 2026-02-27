package dial

import (
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/log"
	"github.com/things-go/go-socks5/statute"
	"net"
	"strconv"
	"strings"
	"time"
)

func (d *Dialer) dialDirectWithoutProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	log.Printf("%s -> DIRECT", addr)
	return goDialer.DialContext(ctx, network, addr)
}

// usedAddr maybe ip:port or hostname:port, it doesn't matter
func (d *Dialer) dialDirectWithHTTPProxy(ctx context.Context, usedAddr string) (net.Conn, error) {
	goDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	log.Printf("%s -> PROXY[%s]", usedAddr, d.dialDirectHTTPProxy)
	conn, err := goDialer.DialContext(ctx, "tcp", d.dialDirectHTTPProxy)
	if err != nil {
		return nil, err
	}

	// HTTP CONNECT
	_, _ = conn.Write([]byte("CONNECT " + usedAddr + " HTTP/1.1\r\n\r\n"))
	connBuf := make([]byte, 256)
	totalNum := 0
	for !strings.Contains(string(connBuf[:totalNum]), "\r\n\r\n") {
		n, err := conn.Read(connBuf[totalNum:])
		totalNum += n
		if err != nil {
			return nil, err
		}
	}

	if strings.Contains(string(connBuf[:totalNum]), "200") {
		// HTTP proxy
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)

			_ = tcpConn.SetReadBuffer(1024 * 1024)
			_ = tcpConn.SetWriteBuffer(1024 * 1024)
		}
		return conn, nil
	}

	return nil, errors.New("PROXY CONNECT ERROR")
}

func (d *Dialer) dialDirectWithSocksProxy(ctx context.Context, network, usedAddr string, isIP bool) (net.Conn, error) {
	goDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	log.Printf("%s -> PROXY[%s]", usedAddr, d.dialDirectSocksProxy)
	conn, err := goDialer.DialContext(ctx, "tcp", d.dialDirectSocksProxy)
	if err != nil {
		return nil, err
	}

	// ---------- SOCKS5 METHOD ----------
	_, err = conn.Write(
		statute.NewMethodRequest(
			statute.VersionSocks5,
			[]byte{statute.MethodNoAuth},
		).Bytes(),
	)
	if err != nil {
		return nil, err
	}

	methodReply, err := statute.ParseMethodReply(conn)
	if err != nil || methodReply.Method != statute.MethodNoAuth || methodReply.Ver != statute.VersionSocks5 {
		return nil, errors.New("SOCKS5 METHOD ERROR")
	}

	// ---------- DST ADDR ----------
	parts := strings.Split(usedAddr, ":")
	dstAddr := statute.AddrSpec{}

	if isIP {
		if len(parts) > 2 {
			dstAddr.AddrType = statute.ATYPIPv6
			dstAddr.IP = net.ParseIP(strings.TrimSuffix(usedAddr, ":"+parts[len(parts)-1]))
			if dstAddr.IP == nil {
				return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
			}
			dstAddr.Port, err = strconv.Atoi(parts[len(parts)-1])
		} else if len(parts) == 2 {
			dstAddr.AddrType = statute.ATYPIPv4
			dstAddr.IP = net.ParseIP(parts[0])
			dstAddr.Port, err = strconv.Atoi(parts[1])
		} else {
			return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
		}
	} else {
		if len(parts) != 2 {
			return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
		}
		dstAddr.AddrType = statute.ATYPDomain
		dstAddr.FQDN = parts[0]
		dstAddr.Port, err = strconv.Atoi(parts[1])
	}

	if err != nil {
		return nil, errors.New("Invalid port for socks proxy: " + usedAddr)
	}

	// ---------- CONNECT ----------
	command := statute.CommandConnect
	if network != "tcp" {
		command = statute.CommandAssociate
	}

	req := statute.Request{
		Version: statute.VersionSocks5,
		Command: command,
		DstAddr: dstAddr,
	}

	_, err = conn.Write(req.Bytes())
	if err != nil {
		return nil, err
	}

	reply, err := statute.ParseReply(conn)
	if err != nil {
		return nil, err
	}
	if reply.Version != statute.VersionSocks5 || reply.Response != statute.RepSuccess {
		return nil, errors.New("SOCKS5 CONNECT ERROR")
	}

	// Performance adjust
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}