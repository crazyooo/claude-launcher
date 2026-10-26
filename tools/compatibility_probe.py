#!/usr/bin/env python3
"""Reproducible local-only socket/descendant probes. Never grants acceptance."""
import ctypes
import errno
import json
import os
import platform
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHILD = '''import socket,sys,json,subprocess,ctypes
c=json.loads(sys.argv[1])
if c.pop('child',False):
 r=subprocess.run([sys.executable,'-c',sys.argv[2],json.dumps(c)],capture_output=True,text=True,timeout=4)
 print(r.stdout,end='');sys.exit(r.returncode)
try:
 if c['kind']=='mach':
  lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib');port=ctypes.c_uint()
  result=lib.bootstrap_look_up(ctypes.c_uint.in_dll(lib,'bootstrap_port').value,b'com.apple.dnssd.service',ctypes.byref(port))
  print(json.dumps({'mach':result}))
 else:
  s=socket.socket(c['family'],c['type']);s.settimeout(1)
  s.connect(c['address'] if isinstance(c['address'],str) else tuple(c['address']))
  if c['kind']=='dns_socket': s.close();print(json.dumps({'connected':True}))
  else: s.sendall(b'probe');print(json.dumps({'echo':s.recv(5)==b'probe'}))
except OSError as e: print(json.dumps({'errno':e.errno}))
'''

def invoke(case, profile=None):
    argv = [sys.executable, '-B', '-c', CHILD, json.dumps(case), CHILD]
    if profile: argv = ['/usr/bin/sandbox-exec', '-p', profile] + argv
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=6)
        return json.loads(result.stdout) if result.returncode == 0 else {'processExit': result.returncode}
    except (ValueError, subprocess.TimeoutExpired): return {'error': 'invalid-result-or-timeout'}

def fixture(family, kind):
    sock = socket.socket(family, kind)
    if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    host = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    sock.bind((host, 0));sock.settimeout(.2)
    if kind == socket.SOCK_STREAM: sock.listen()
    def serve():
        while True:
            try:
                if kind == socket.SOCK_DGRAM:
                    data, addr = sock.recvfrom(32);sock.sendto(data, addr)
                else:
                    conn, _ = sock.accept()
                    with conn: conn.sendall(conn.recv(32))
            except socket.timeout: continue
            except OSError: return
    threading.Thread(target=serve, daemon=True).start()
    return sock, {'kind':'socket','family':family,'type':kind,'address':[host,sock.getsockname()[1]]}

def main():
    sockets=[];cases=[]
    for name,family,kind in [('gateway',socket.AF_INET,socket.SOCK_STREAM),('ipv4',socket.AF_INET,socket.SOCK_STREAM),('ipv6',socket.AF_INET6,socket.SOCK_STREAM),('udp4',socket.AF_INET,socket.SOCK_DGRAM),('udp6',socket.AF_INET6,socket.SOCK_DGRAM)]:
        sock,case=fixture(family,kind);sockets.append(sock);cases.append((name,case))
    port=cases[0][1]['address'][1]
    profile=f'(version 1)(allow default)(deny network*)(deny mach-lookup)(allow network-outbound (remote tcp "localhost:{port}"))'
    results=[]
    for name,case in cases:
        baseline=invoke(case)
        for child in [False,True]:
            observed=invoke(dict(case,child=child),profile)
            passed=baseline.get('echo') is True and (observed.get('echo') is True if name=='gateway' else observed.get('errno') in (errno.EPERM,errno.EACCES))
            results.append(dict(name=name,descendant=child,passed=passed,baseline=baseline,restricted=observed))
    mach={'kind':'mach'}
    dns={'kind':'dns_socket','family':socket.AF_UNIX,'type':socket.SOCK_STREAM,'address':'/private/var/run/mDNSResponder'}
    report={'os':platform.platform(),'localChecks':results,'dnsMach':{'baseline':invoke(mach),'restricted':invoke(mach,profile)},'dnsSocket':{'baseline':invoke(dns),'restricted':invoke(dns,profile)},'productionLaunchAllowed':False,'unverified':['Desktop helpers and brokered networking','CLI real authenticated streaming','background supervisor and update restart','actual proxy and pinned exit']}
    env={'HOME':'/var/empty','PATH':'/usr/bin:/bin','DISABLE_AUTOUPDATER':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
    cli=Path.home()/'.local/bin/claude'
    result=subprocess.run(['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)(deny mach-lookup)(deny file-write*)',str(cli),'--version'],env=env,capture_output=True,text=True,timeout=15)
    report['cliVersionProbe']={'exitCode':result.returncode,'version':result.stdout.strip()[:80] if result.returncode==0 else None,'runtimeProven':False}
    for sock in sockets:sock.close()
    print(json.dumps(report,indent=2,ensure_ascii=False))
    return 0 if all(x['passed'] for x in results) else 1
if __name__=='__main__':
    try: sys.exit(main())
    except Exception as error:
        print(json.dumps({'productionLaunchAllowed':False,'status':'inconclusive','errorType':type(error).__name__}))
        sys.exit(1)
