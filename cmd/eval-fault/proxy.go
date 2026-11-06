package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// proxy is an in-process TCP forwarder placed between UniDB-Go and one
// database server. It injects faults without touching the shared server:
// refuse closes the listener (new connections get ECONNREFUSED), cutAll
// closes every relayed connection, blackhole keeps sockets open but relays
// nothing (new connections are accepted and never answered), and latency
// delays every client-to-server chunk by a fixed one-way delay.
type proxy struct {
	name, addr, target string

	mu      sync.Mutex
	ln      net.Listener
	links   map[*link]struct{}
	held    map[net.Conn]struct{} // connections accepted while blackholed
	gate    chan struct{}         // closed while traffic flows
	blocked bool

	latency    atomic.Int64 // one-way delay added to client->server chunks (ns)
	cutAt      atomic.Int64 // cut all links once s2c reaches this; 0 = off
	commitTrap atomic.Bool  // forward the next client chunk, then drop replies and cut
	dropS2C    atomic.Bool

	s2c, c2s, chunks, accepted atomic.Int64
}

// link is one relayed client connection and its upstream connection.
type link struct {
	client, server net.Conn
	once           sync.Once
	done           chan struct{}
}

func (l *link) close() {
	l.once.Do(func() {
		close(l.done)
		l.client.Close()
		l.server.Close()
	})
}

type chunk struct {
	b []byte
	t time.Time
}

// newProxy listens on a free loopback port and forwards to target.
func newProxy(name, target string) (*proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{name: name, addr: ln.Addr().String(), target: target, ln: ln,
		links: map[*link]struct{}{}, held: map[net.Conn]struct{}{}, gate: make(chan struct{})}
	close(p.gate)
	go p.serve(ln)
	return p, nil
}

func (p *proxy) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		p.handle(c)
	}
}

func (p *proxy) handle(c net.Conn) {
	p.mu.Lock()
	if p.blocked {
		p.held[c] = struct{}{}
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	s, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		c.Close()
		return
	}
	l := &link{client: c, server: s, done: make(chan struct{})}
	p.mu.Lock()
	p.links[l] = struct{}{}
	p.mu.Unlock()
	queue := make(chan chunk, 4096)
	go p.readClient(l, queue)
	go p.writeServer(l, queue)
	go p.relayServer(l)
}

func (p *proxy) wait(l *link) bool {
	p.mu.Lock()
	g := p.gate
	p.mu.Unlock()
	select {
	case <-g:
		return true
	case <-l.done:
		return false
	}
}

func (p *proxy) readClient(l *link, q chan<- chunk) {
	defer close(q)
	for {
		buf := make([]byte, 32<<10)
		n, err := l.client.Read(buf)
		if n > 0 {
			q <- chunk{buf[:n], time.Now()}
		}
		if err != nil {
			p.drop(l)
			return
		}
	}
}

func (p *proxy) writeServer(l *link, q <-chan chunk) {
	for c := range q {
		if !p.wait(l) {
			return
		}
		if d := time.Duration(p.latency.Load()); d > 0 {
			time.Sleep(time.Until(c.t.Add(d)))
		}
		trap := p.commitTrap.CompareAndSwap(true, false)
		if trap {
			p.dropS2C.Store(true)
		}
		if _, err := l.server.Write(c.b); err != nil {
			p.drop(l)
			return
		}
		p.c2s.Add(int64(len(c.b)))
		p.chunks.Add(1)
		if trap {
			// The request reached the server; its reply never reaches the client.
			go func() { time.Sleep(200 * time.Millisecond); p.cutAll() }()
		}
	}
}

func (p *proxy) relayServer(l *link) {
	buf := make([]byte, 32<<10)
	for {
		n, err := l.server.Read(buf)
		if n > 0 {
			if !p.wait(l) {
				return
			}
			if p.dropS2C.Load() {
				continue
			}
			if _, werr := l.client.Write(buf[:n]); werr != nil {
				p.drop(l)
				return
			}
			total := p.s2c.Add(int64(n))
			if at := p.cutAt.Load(); at > 0 && total >= at && p.cutAt.CompareAndSwap(at, 0) {
				p.cutAll()
				return
			}
		}
		if err != nil {
			p.drop(l)
			return
		}
	}
}

func (p *proxy) drop(l *link) {
	l.close()
	p.mu.Lock()
	delete(p.links, l)
	p.mu.Unlock()
}

// cutAll closes every relayed and every held connection.
func (p *proxy) cutAll() {
	p.mu.Lock()
	links := p.links
	held := p.held
	p.links, p.held = map[*link]struct{}{}, map[net.Conn]struct{}{}
	p.mu.Unlock()
	for l := range links {
		l.close()
	}
	for c := range held {
		c.Close()
	}
}

// refuse simulates a server that is down: the listener is closed, so new
// connections are refused, and every live connection is cut.
func (p *proxy) refuse() {
	p.mu.Lock()
	if p.ln != nil {
		p.ln.Close()
		p.ln = nil
	}
	p.mu.Unlock()
	p.cutAll()
}

// blackhole stops relaying on live connections and holds new ones unanswered.
func (p *proxy) blackhole() {
	p.mu.Lock()
	if !p.blocked {
		p.blocked = true
		p.gate = make(chan struct{})
	}
	p.mu.Unlock()
}

// cutAfter arms a cut of all connections after n more server->client bytes.
func (p *proxy) cutAfter(n int64) { p.cutAt.Store(p.s2c.Load() + n) }

// heal restores normal forwarding. Held (blackholed) connections are closed,
// as a partition that ends leaves them broken; relayed ones resume.
func (p *proxy) heal() error {
	p.latency.Store(0)
	p.cutAt.Store(0)
	p.commitTrap.Store(false)
	p.dropS2C.Store(false)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blocked {
		p.blocked = false
		close(p.gate)
	}
	for c := range p.held {
		c.Close()
	}
	p.held = map[net.Conn]struct{}{}
	if p.ln == nil {
		ln, err := net.Listen("tcp", p.addr)
		if err != nil {
			return err
		}
		p.ln = ln
		go p.serve(ln)
	}
	return nil
}

// open reports the number of relayed plus held client connections.
func (p *proxy) open() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.links) + len(p.held)
}
