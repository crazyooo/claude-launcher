#!/usr/bin/env python3
"""Loopback-only integration and fault injection against the real Swift gateway."""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/'.build/debug/launcher-tool'

def exact(s,n):
    data=b''
    while len(data)<n:
        chunk=s.recv(n-len(data))
        if not chunk: raise EOFError()
        data+=chunk
    return data

def headers(s):
    data=b''
    while not data.endswith(b'\r\n\r\n'):
        data+=exact(s,1)
        if len(data)>32768: raise ValueError()
    return data

def listener():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen();return s

def port():
    s=listener();p=s.getsockname()[1];s.close();return p

class Upstream:
    def __init__(self,protocol):
        self.protocol=protocol;self.socket=listener();self.port=self.socket.getsockname()[1];self.connections=[];self.stopped=False
        threading.Thread(target=self.serve,daemon=True).start()
    def serve(self):
        while not self.stopped:
            try:s,_=self.socket.accept()
            except OSError:return
            self.connections.append(s);threading.Thread(target=self.client,args=(s,),daemon=True).start()
    def client(self,s):
        try:
            s.settimeout(12)
            if self.protocol=='http':
                h=headers(s);assert h.startswith(b'CONNECT ')
                # Deliberately split the handshake; preserve post-header read-ahead.
                s.sendall(b'HTTP/1.1 200 OK\r\n');time.sleep(.01);s.sendall(b'\r\n')
            else:
                assert exact(s,3)==b'\x05\x01\x00';s.sendall(b'\x05\x00')
                assert exact(s,4)==b'\x05\x01\x00\x03';n=exact(s,1)[0];exact(s,n+2)
                s.sendall(b'\x05\x00\x00\x03\x03abc\x00\x50')
            while True:
                data=s.recv(65536)
                if not data:s.sendall(b'FINAL');s.shutdown(socket.SHUT_WR);return
                if data.startswith(b'GET /hello'):
                    assert b'Proxy-Authorization' not in data
                    s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello');return
                s.sendall(data)
        except (OSError,EOFError):pass
        finally:s.close()
    def close(self):
        self.stopped=True;self.socket.close()
        for s in self.connections:
            try:s.shutdown(socket.SHUT_RDWR);s.close()
            except OSError:pass

def assert_ipv4_boundary(port_number, upstream):
    """Exercise real parser/listener; rejected requests must never reach upstream."""
    before = len(upstream.connections)
    for host in ('[::1]', '[2001:db8::1]', '[::ffff:127.0.0.1]',
                 '[::ffff:7f00:1]', '[fe80::1%25lo0]'):
        for request in ('CONNECT ' + host + ':443', 'GET http://' + host + ':80/hello'):
            with socket.create_connection(('127.0.0.1', port_number), 2) as client:
                client.settimeout(3)
                client.sendall((request + ' HTTP/1.1\r\nHost: example.com\r\n\r\n').encode())
                try:
                    response = headers(client)
                except (EOFError, ConnectionResetError):
                    response = b''
                assert not response.startswith(b'HTTP/1.1 200'), request
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        try:
            client.connect(('::1', port_number))
        except (ConnectionRefusedError, OSError):
            pass
        else:
            raise AssertionError('IPv6 loopback listener unexpectedly reachable')
    assert len(upstream.connections) == before, 'IPv6 target reached upstream'


class RunningGateway:
    def __init__(self,protocol,upstream):
        self.temp=tempfile.TemporaryDirectory();self.normal=port();self.probe=port()
        config={'protocolName':protocol,'host':'127.0.0.1','port':upstream.port,'gatewayPort':self.normal,'probePort':self.probe,'expectedIP':'192.0.2.1','confirmed':True,'authentication':False}
        file=Path(self.temp.name)/'config.json';file.write_text(json.dumps(config))
        self.process=subprocess.Popen([str(TOOL),'gateway',str(file)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ready,_,_=select.select([self.process.stdout],[],[],5);assert ready,'gateway startup timeout'
        assert self.process.stdout.readline()==b'READY\n'
        self.beating=True;self.lock=threading.Lock()
        threading.Thread(target=self.beat,daemon=True).start()
    def command(self,command):
        with self.lock:
            try:self.process.stdin.write(command.encode()+b'\n');self.process.stdin.flush()
            except (OSError,ValueError):pass
    def beat(self):
        while self.beating:self.command('HEARTBEAT');time.sleep(.25)
    def connect(self,probe=False):
        s=socket.create_connection(('127.0.0.1',self.probe if probe else self.normal),2);s.settimeout(5)
        s.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n')
        assert headers(s).startswith(b'HTTP/1.1 200'), 'CONNECT denied';return s
    def denied(self):
        try:
            s=self.connect();s.close();return False
        except (EOFError,OSError,AssertionError):return True
    def close(self):
        self.beating=False
        if self.process.poll() is None:
            self.process.stdin.close()
            try:self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.temp.cleanup()

def run():
    results=[]
    for protocol in ('http','socks5'):
        upstream=Upstream(protocol);gateway=RunningGateway(protocol,upstream)
        try:
            assert gateway.denied();results.append(protocol+':default-block')
            gateway.command('ALLOW');time.sleep(.1)
            assert_ipv4_boundary(gateway.normal, upstream);results.append(protocol+':ipv4-boundary')
            s=gateway.connect();payload=os.urandom(256*1024)
            # Send/read in chunks to assert bounded streaming, not whole-body buffering.
            for offset in range(0,len(payload),4096):
                chunk=payload[offset:offset+4096];s.sendall(chunk);assert exact(s,len(chunk))==chunk
            s.shutdown(socket.SHUT_WR);assert exact(s,5)==b'FINAL';s.close();results.append(protocol+':stream-and-half-close')
            s=socket.create_connection(('127.0.0.1',gateway.normal));s.settimeout(4)
            s.sendall(b'GET http://example.com/hello HTTP/1.1\r\nHost: fake\r\nProxy-Authorization: redacted-test\r\n\r\n');assert b'200' in headers(s);assert exact(s,5)==b'hello';s.close();results.append(protocol+':plain-http')
            try:gateway.connect(probe=True);raise AssertionError('probe listener accepted arbitrary target')
            except (EOFError,OSError,AssertionError) as error:
                if str(error)=='probe listener accepted arbitrary target':raise
            results.append(protocol+':probe-target-restriction')
            s=gateway.connect();gateway.command('BLOCK');time.sleep(.1);assert s.recv(1)==b'';assert gateway.denied();s.close();results.append(protocol+':block-closes-existing')
            gateway.command('ALLOW');time.sleep(.1);s=gateway.connect();gateway.beating=False;start=time.monotonic();assert s.recv(1)==b'';assert time.monotonic()-start<3.5;assert gateway.denied();s.close();results.append(protocol+':heartbeat-timeout')
            gateway.command('HEARTBEAT');time.sleep(.1);assert gateway.denied();results.append(protocol+':heartbeat-does-not-resume')
            gateway.command('ALLOW');time.sleep(.1);s=gateway.connect();upstream.close();assert s.recv(1)==b'';s.close();assert gateway.denied();results.append(protocol+':upstream-failure-no-fallback')
        finally:gateway.close();upstream.close()
    upstream=Upstream('http');gateway=RunningGateway('http',upstream)
    try:
        duplicate=subprocess.Popen([str(TOOL),'gateway',str(Path(gateway.temp.name)/'config.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert duplicate.wait(timeout=5)!=0;results.append('port-conflict')
        gateway.command('ALLOW');time.sleep(.1);s=gateway.connect();gateway.process.kill();gateway.process.wait();assert s.recv(1)==b'';s.close();results.append('gateway-kill')
    finally:gateway.close();upstream.close()
    print(json.dumps({'passed':results,'count':len(results),'scope':'local fixtures only; no real Claude acceptance'},indent=2))
if __name__=='__main__':run()
