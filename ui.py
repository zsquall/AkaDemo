import ctypes
import sys
import re
from ctypes import *

print "please enter the Authorization header, and press ctrl-d for end"
authHeaderLines = sys.stdin.readlines()
authHeader = ""

print "analyzing ... ..."

for line in authHeaderLines:
    authHeader = authHeader + line;
authPars = authHeader.split(',');

paraCol = {}
for authPar in authPars:
    pat = re.match(r'(.+?) ?= ?"?(.+?)"?$', authPar)
    par = ""
    val = ""
    pat1 = re.match(r'(^.+) (.+$)', pat.group(1))
    if pat1:
        par = pat1.group(2)
    else:
        par = pat.group(1)
    val = pat.group(2)
    paraCol[par] = val

usr_name = paraCol['username']
realm = paraCol['realm']
method = 'REGISTER';
uri = paraCol['uri']
nc = paraCol['nc']
cnonce = paraCol['cnonce']
qop = 'auth';
nonce= paraCol['nonce']
al = paraCol['algorithm']

sharekey = '465b5ce8b199b49faa5f0a2ee238a6bc';
print "====================input parameters================="
print "usr_name :", usr_name
print "realm    :", realm
print "method   :", method 
print "uri      :", uri 
print "nc       :", nc 
print "cnonce   :", cnonce 
print "qop      :", qop 
print "nonce    :", nonce 
print "sharekey :", sharekey 
print "=====================================================\r\n"

pdll = ctypes.CDLL('./AKA.so')
res = create_string_buffer(100)
print "====================OUT PUT=========================="
pdll.runAKA(usr_name, realm, method, uri, nc, cnonce, qop, nonce, sharekey, al, res);
print "=====================================================\r\n"

print "====================RESULT=========================="
print  res.raw, " VS ", paraCol['response']
print "====================================================="
