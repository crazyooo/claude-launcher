#!/usr/bin/env python3
"""Exercise the new gateway with loopback fixtures; never contacts Claude or 1082."""
import base64
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from gateway_integration import Upstream, TOOL, headers, exact, listener, assert_ipv4_boundary

HOSTS = ('claude.ai', 'api.anthropic.com', 'platform.claude.com')

def disconnected(sock):
    sock.settimeout(4)
    try:
        return sock.recv(1) == b''
    except (ConnectionResetError, BrokenPipeError):
        return True

class Gateway:
    def __init__(self, upstream, protocol, port=0):
        self.condition = threading.Condition()
        self.writer = threading.Lock()
        self.responses = {}
        self.latest = None
        self.ended = False
        self.beating = True
        self.stop = threading.Event()
        # Retain tiny fixture configs for diagnosis; no credentials are stored.
        self.directory = Path(tempfile.mkdtemp(prefix='connector-test-'))
        self.config = self.directory / 'connector.json'
        self.config.write_text(json.dumps(dict(version=1, upstreamProtocol=protocol,
            upstreamHost='127.0.0.1', upstreamPort=upstream.port,
            expectedIPv4='192.0.2.1', expectedIPv6='', listenPort=port)))
        self.process = subprocess.Popen([str(TOOL), 'connector-gateway', str(self.config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        threading.Thread(target=self.read, daemon=True).start()
        self.wait(lambda: self.latest and self.latest['port'])
        self.port = self.latest['port']
        self.command('heartbeat')
        self.heartbeat = threading.Thread(target=self.beat, daemon=True)
        self.heartbeat.start()
    def wait(self, predicate):
        deadline = time.monotonic() + 5
        with self.condition:
            while not predicate():
                if self.ended:
                    raise RuntimeError('gateway ended before reply')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('control deadline')
                self.condition.wait(remaining)
    def read(self):
        try:
            while True:
                line = self.process.stdout.readline(131073)
                if not line or len(line) > 131072:
                    return
                value = json.loads(line)
                with self.condition:
                    self.latest = value['snapshot']
                    identity = value.get('commandID')
                    if identity:
                        self.responses[identity.lower()] = value
                    self.condition.notify_all()
        finally:
            with self.condition:
                self.ended = True
                self.condition.notify_all()
    def command(self, operation, **fields):
        identity = str(uuid.uuid4())
        command = dict(id=identity, operation=operation, epoch=0, manual=False)
        command.update(fields)
        with self.writer:
            self.process.stdin.write(json.dumps(command).encode() + b'\n')
            self.process.stdin.flush()
        self.wait(lambda: identity in self.responses)
        with self.condition:
            return self.responses.pop(identity)
    def beat(self):
        while not self.stop.wait(.25):
            if self.beating:
                try:
                    self.command('heartbeat')
                except (OSError, ValueError, RuntimeError, TimeoutError):
                    return
    def connect(self, target='example.com:443', authorization=None, accepted=True):
        sock = socket.create_connection(('127.0.0.1', self.port), 2)
        sock.settimeout(4)
        credential = '' if authorization is None else 'Proxy-Authorization: ' + authorization + '\r\n'
        sock.sendall(('CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n' + credential + '\r\n').encode())
        try:
            response = headers(sock)
            assert response.startswith(b'HTTP/1.1 200') == accepted, response
        except (EOFError, ConnectionResetError):
            if accepted:
                sock.close()
                raise
        return sock
    def allow(self):
        self.command('heartbeat')
        identity = str(uuid.uuid4()); token = 'a' * 64
        reply = self.command('beginProbe', epoch=self.latest['epoch'], checkID=identity,
                             authorization=token, manual=True)
        assert reply['accepted']
        epoch = reply['snapshot']['epoch']
        auth = 'Basic ' + base64.b64encode(('probe:' + token).encode()).decode()
        self.connect('example.com:443', auth, False).close()
        probes = [self.connect(host + ':443', auth) for host in HOSTS]
        self.connect(HOSTS[0] + ':443', auth, False).close()
        assert self.command('revokeProbe', epoch=epoch, checkID=identity)['accepted']
        for sock in probes:
            assert disconnected(sock)
            sock.close()
        self.connect(HOSTS[0] + ':443', auth, False).close()
        assert not self.command('allow', epoch=epoch - 1, checkID=identity)['accepted']
        assert self.command('allow', epoch=epoch, checkID=identity)['accepted']
        return epoch, identity
    def close(self):
        self.stop.set(); self.heartbeat.join(6)
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=4)
        self.process.stdout.close()

def run():
    checks = []
    for protocol in ('http', 'socks5'):
        upstream = Upstream(protocol); gateway = Gateway(upstream, protocol)
        try:
            gateway.connect(accepted=False).close()
            epoch, identity = gateway.allow()
            checks += [protocol + ':default-block', protocol + ':scoped-once-revoked-probes']
            assert_ipv4_boundary(gateway.port, upstream)
            checks.append(protocol + ':ipv4-boundary')
            sock = gateway.connect()
            for _ in range(64):
                part = os.urandom(4096); sock.sendall(part); assert exact(sock, len(part)) == part
            sock.shutdown(socket.SHUT_WR); assert exact(sock, 5) == b'FINAL'; sock.close()
            checks.append(protocol + ':stream-half-close')
            sock = socket.create_connection(('127.0.0.1', gateway.port)); sock.settimeout(4)
            sock.sendall(b'GET http://example.com/hello HTTP/1.1\r\nHost: example.com\r\n\r\n')
            assert b'200' in headers(sock); assert exact(sock, 5) == b'hello'; sock.close()
            checks.append(protocol + ':plain-http')
            # A periodic check revokes only its probe connections, not a live business stream.
            stream = gateway.connect()
            check = str(uuid.uuid4()); token = 'b' * 64
            started = gateway.command('beginProbe', epoch=gateway.latest['epoch'], checkID=check,
                                      authorization=token, manual=False)
            assert started['accepted']
            auth = 'Basic ' + base64.b64encode(('probe:' + token).encode()).decode()
            probes = [gateway.connect(host + ':443', auth) for host in HOSTS]
            assert gateway.command('revokeProbe', epoch=started['snapshot']['epoch'], checkID=check)['accepted']
            for probe in probes:
                assert disconnected(probe); probe.close()
            assert gateway.command('renew', epoch=started['snapshot']['epoch'], checkID=check)['accepted']
            stream.sendall(b'renewal-survived'); assert exact(stream, 16) == b'renewal-survived'
            stream.close(); checks.append(protocol + ':periodic-renewal-preserves-stream')
            sock = gateway.connect(); assert gateway.command('block', reason='manual_block')['accepted']
            assert disconnected(sock); sock.close(); gateway.connect(accepted=False).close()
            assert not gateway.command('allow', epoch=epoch, checkID=identity)['accepted']
            gateway.command('heartbeat'); gateway.connect(accepted=False).close()
            checks.append(protocol + ':block-old-epoch-no-auto-recovery')
            gateway.allow(); sock = gateway.connect(); gateway.beating = False
            start = time.monotonic(); assert disconnected(sock); assert time.monotonic() - start < 3.8
            sock.close(); gateway.command('heartbeat'); gateway.connect(accepted=False).close()
            checks.append(protocol + ':heartbeat-existing-new')
            gateway.beating = True; gateway.allow()
            canary = listener(); canary.settimeout(.4)
            try:
                upstream.stopped = True
                wake = socket.create_connection(("127.0.0.1", upstream.port), 2); wake.close()
                time.sleep(.1)
                upstream.close()
                gateway.connect('127.0.0.1:' + str(canary.getsockname()[1]), accepted=False).close()
                try:
                    client, _ = canary.accept(); client.close()
                    raise AssertionError('direct fallback reached canary')
                except socket.timeout:
                    pass
            finally:
                canary.close()
            checks.append(protocol + ':upstream-no-direct-fallback')
        finally:
            gateway.close(); upstream.close()
    # Port conflict and abrupt control/process loss are separate instances.
    for action in ('occupied', 'eof', 'kill', 'oversized'):
        upstream = Upstream('http'); gateway = Gateway(upstream, 'http')
        try:
            gateway.allow(); sock = gateway.connect()
            if action == 'occupied':
                config = json.loads(gateway.config.read_text()); config['listenPort'] = gateway.port
                other = gateway.directory / 'occupied.json'; other.write_text(json.dumps(config))
                child = subprocess.Popen([str(TOOL), 'connector-gateway', str(other)], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                assert child.wait(timeout=5) != 0
                child.stdin.close(); child.stdout.close()
                sock.sendall(b'original-alive'); assert exact(sock, 14) == b'original-alive'
            else:
                gateway.stop.set(); gateway.heartbeat.join(6)
                if action == 'eof': gateway.process.stdin.close()
                elif action == 'kill': gateway.process.kill()
                else:
                    gateway.process.stdin.write(b'x' * 8193 + b'\n'); gateway.process.stdin.flush()
                assert disconnected(sock); gateway.process.wait(timeout=5)
            sock.close(); checks.append(action)
        finally:
            gateway.close(); upstream.close()
    checks.extend(transactions())
    checks.extend(holds())
    print(json.dumps({'passed': checks, 'count': len(checks), 'scope': 'loopback fixtures, no client isolation acceptance'}, indent=2))

def transactions():
    checks = []
    for mode in ('missing-pf', 'bad-samples', 'service-429', 'service-500', 'missing-service', 'incomplete-budget', 'cancel-probing', 'expired'):
        upstream = Upstream('http'); gateway = Gateway(upstream, 'http')
        try:
            epoch, old_check = gateway.allow()
            stream = gateway.connect()
            snapshot = gateway.latest
            binding = dict(id=str(uuid.uuid4()), gatewayInstance=snapshot['instanceID'],
                configurationDigest=snapshot['configDigest'], initialEpoch=snapshot['epoch'],
                pf=dict(requestID='f' * 32, expectedRevision=0, planID='f' * 32,
                        planSHA256='f' * 64, runtimeSHA256='f' * 64,
                        serviceInstance='f' * 32, generation='f' * 32, receivedNotBefore=time.time()))
            reserved = gateway.command('reserveTransaction', transaction=binding)
            assert reserved['accepted'] and reserved['snapshot']['transaction']['phase'] == 'reserved'
            assert not reserved['snapshot']['transaction']['drainPending']
            assert disconnected(stream); stream.close()
            for operation in ('beginProbe', 'allow', 'renew'):
                assert not gateway.command(operation, epoch=epoch, checkID=old_check,
                                           authorization='a' * 64, manual=True)['accepted']
            repeated = gateway.command('reserveTransaction', transaction=binding)
            assert repeated['accepted'] and repeated['snapshot']['epoch'] == reserved['snapshot']['epoch']
            gateway.connect(accepted=False).close()
            checks.append(mode + ':reserve-drains-and-fences-old-commands')
            if mode == 'expired':
                time.sleep(12.2)
                rejected = gateway.command('commitTransaction', transaction=binding)
                assert not rejected['accepted'] and rejected['snapshot']['transaction']['phase'] == 'expired'
            else:
                check = str(uuid.uuid4()); token = 'c' * 64
                assert gateway.command('beginTransactionProbe', transaction=binding,
                                       checkID=check, authorization=token)['accepted']
                auth = 'Basic ' + base64.b64encode(('probe:' + token).encode()).decode()
                probe_hosts = HOSTS if mode == 'incomplete-budget' else HOSTS + ('claude.ai', 'api.anthropic.com')
                probes = [gateway.connect(host + ':443', auth) for host in probe_hosts]
                silent = socket.create_connection(('127.0.0.1', gateway.port), 2)
                # Let the listener register the socket before testing its drain.
                time.sleep(.1)
                services = {'desktop': {'status': 200}, 'api': {'status': 401}}
                if mode == 'service-429': services['api']['status'] = 429
                if mode == 'service-500': services['desktop']['status'] = 500
                if mode == 'missing-service': services.pop('api')
                samples = {host: '192.0.2.1' for host in HOSTS}
                if mode == 'bad-samples': samples[HOSTS[0]] = '192.0.2.2'
                if mode == 'cancel-probing':
                    prepared = gateway.command('cancelTransaction', transaction=binding)
                    assert prepared['accepted'] and prepared['snapshot']['transaction']['phase'] == 'cancelled'
                    assert not prepared['snapshot']['transaction']['drainPending']
                else:
                    prepared = gateway.command('prepareTransaction', transaction=binding, checkID=check, samples=samples, services=services)
                    assert prepared['accepted'] == (mode == 'missing-pf')
                for probe in probes:
                    assert disconnected(probe); probe.close()
                assert disconnected(silent); silent.close()
                gateway.connect(HOSTS[0] + ':443', auth, False).close()
                gateway.connect(accepted=False).close()
                if mode == 'missing-pf':
                    assert prepared['snapshot']['transaction']['phase'] == 'prepared'
                    replay = gateway.command('prepareTransaction', transaction=binding, checkID=check, samples=samples, services=services)
                    assert replay['accepted'] and replay['snapshot']['epoch'] == prepared['snapshot']['epoch']
                    # Production verifier reads the actual root report; fabricated selectors cannot grant traffic.
                    rejected = gateway.command('commitTransaction', transaction=binding)
                    assert not rejected['accepted'] and rejected['snapshot']['state'] == 'blocked'
                    assert rejected['snapshot']['reason'] == 'pf_evidence_unavailable'
                checks.append(mode + ':probe-drain-no-early-forwarding')
            cancelled = gateway.command('cancelTransaction', transaction=binding)
            assert cancelled['accepted'] and not cancelled['snapshot']['transaction']['drainPending']
            assert not gateway.command('beginProbe', epoch=gateway.latest['epoch'], checkID=str(uuid.uuid4()),
                                       authorization='a' * 64, manual=True)['accepted']
            released = gateway.command('leaveCoordinatedMode', transaction=binding)
            assert released['accepted'] and released['snapshot']['transaction']['phase'] == 'released'
            assert not released['snapshot']['transaction']['drainPending']
            changed = dict(binding, initialEpoch=released['snapshot']['epoch'])
            assert not gateway.command('reserveTransaction', transaction=changed)['accepted']
            assert not gateway.command('commitTransaction', transaction=binding)['accepted']
            replay = gateway.command('leaveCoordinatedMode', transaction=binding)
            assert replay['accepted'] and replay['snapshot']['epoch'] == released['snapshot']['epoch']
            gateway.allow()
            sock = gateway.connect(); sock.sendall(b'back'); assert exact(sock, 4) == b'back'; sock.close()
            checks.append(mode + ':explicit-leave-with-replay-isolation')
        finally:
            gateway.close(); upstream.close()
    return checks

def holds():
    checks = []
    for mode in ('delayed-attach', 'cancel', 'heartbeat'):
        upstream = Upstream('http'); gateway = Gateway(upstream, 'http')
        try:
            gateway.allow(); stream = gateway.connect()
            snapshot = gateway.latest
            hold = dict(id=str(uuid.uuid4()), gatewayInstance=snapshot['instanceID'],
                        configurationDigest=snapshot['configDigest'], initialEpoch=snapshot['epoch'])
            held = gateway.command('hold', hold=hold)
            assert held['accepted'] and held['snapshot']['hold']['phase'] == 'held'
            assert not held['snapshot']['hold']['drainPending']
            assert disconnected(stream); stream.close()
            binding = dict(hold, pf=dict(requestID='f' * 32, expectedRevision=0, planID='f' * 32,
                planSHA256='f' * 64, runtimeSHA256='f' * 64, serviceInstance='f' * 32,
                generation='f' * 32, receivedNotBefore=time.time()))
            for operation in ('beginProbe', 'allow', 'renew'):
                assert not gateway.command(operation, epoch=gateway.latest['epoch'], checkID=str(uuid.uuid4()),
                                           authorization='a' * 64, manual=True)['accepted']
            assert not gateway.command('reserveTransaction', transaction=binding)['accepted']
            gateway.connect(accepted=False).close()
            checks.append(mode + ':held-drains-and-fences-v1')
            with (gateway.directory / 'connector-gateway.lifetime').open('r+') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    raise AssertionError('running gateway did not hold lifetime lock')
                except BlockingIOError:
                    pass
            if mode == 'delayed-attach':
                time.sleep(12.2)
                assert gateway.command('hold', hold=hold)['accepted']
                attached = gateway.command('attachTransaction', hold=hold, transaction=binding)
                assert attached['accepted'] and attached['snapshot']['transaction']['phase'] == 'reserved'
                assert gateway.command('attachTransaction', hold=hold, transaction=binding)['accepted']
                changed = dict(binding, pf=dict(binding['pf'], generation='e' * 32))
                assert not gateway.command('attachTransaction', hold=hold, transaction=changed)['accepted']
                assert not gateway.command('beginTransactionProbe', transaction=binding, checkID=str(uuid.uuid4()),
                                           authorization='a' * 64)['accepted']
                check = str(uuid.uuid4()); token = 'd' * 64
                assert gateway.command('beginTransactionProbe', hold=hold, transaction=binding,
                                       checkID=check, authorization=token)['accepted']
                auth = 'Basic ' + base64.b64encode(('probe:' + token).encode()).decode()
                probe_hosts = HOSTS if mode == 'incomplete-budget' else HOSTS + ('claude.ai', 'api.anthropic.com')
                probes = [gateway.connect(host + ':443', auth) for host in probe_hosts]
                prepared = gateway.command('prepareTransaction', hold=hold, transaction=binding,
                    checkID=check, samples={host: '192.0.2.1' for host in HOSTS},
                    services={'desktop': {'status': 200}, 'api': {'status': 403}})
                assert prepared['accepted'] and prepared['snapshot']['transaction']['phase'] == 'prepared'
                for probe in probes:
                    assert disconnected(probe); probe.close()
                # Exact attach retries after preparation must not renew its original deadline.
                time.sleep(6)
                assert gateway.command('attachTransaction', hold=hold, transaction=binding)['accepted']
                time.sleep(6.2)
                late = gateway.command('commitTransaction', hold=hold, transaction=binding)
                assert not late['accepted'] and late['snapshot']['transaction']['phase'] == 'expired'
                checks.append('hold:authorization-wait-excluded-attach-budget-never-renewed')
            elif mode == 'heartbeat':
                gateway.beating = False; time.sleep(3.3)
                gateway.command('heartbeat'); gateway.beating = True
                rejected = gateway.command('attachTransaction', hold=hold, transaction=binding)
                assert not rejected['accepted'] and rejected['snapshot']['hold']['phase'] == 'interrupted'
                checks.append('hold:heartbeat-loss-cannot-be-revived')
            cancelled = gateway.command('cancelHold', hold=hold)
            assert cancelled['accepted'] and cancelled['snapshot']['hold']['phase'] == 'cancelled'
            assert not gateway.command('attachTransaction', hold=hold, transaction=binding)['accepted']
            assert not gateway.command('beginProbe', epoch=gateway.latest['epoch'], checkID=str(uuid.uuid4()),
                                       authorization='a' * 64, manual=True)['accepted']
            released = gateway.command('leaveHold', hold=hold)
            assert released['accepted'] and released['snapshot']['hold']['phase'] == 'released'
            assert not gateway.command('hold', hold=hold)['accepted']
            assert not gateway.command('attachTransaction', hold=hold, transaction=binding)['accepted']
            gateway.allow()
            checks.append(mode + ':terminal-fence-and-explicit-leave')
            gateway.close()
            with (gateway.directory / 'connector-gateway.lifetime').open('r+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            checks.append(mode + ':lifetime-released-after-process-exit')
        finally:
            gateway.close(); upstream.close()
    return checks

if __name__ == '__main__':
    run()
