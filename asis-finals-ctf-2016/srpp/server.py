#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import time 
from hashlib import *
from thread import *
from Crypto.Util.number import *
from os import urandom
from random import *
from string import *
from secret import password, flag



_port = int(sys.argv[1])
_timeout = 3 
_host = ''
_bufsize = 4096

_logfile = open(str(sys.argv[0]) + '.log', 'a')

_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_socket.bind((_host, _port))
_socket.listen(_bufsize)
_taskname = 'SRPP'
_hash = 'sha512'


def Hash(*args):
    a = ':'.join(str(a) for a in args)
    return int(sha256(a).hexdigest(), 16)


def getParams(nbit):
    N = getPrime(nbit)
    g = 2
    k = Hash(N, g)
    return(N, g, k)


def clientThread(client):
    client.send('Bot detection: Are you ready?' + '\n')
    A = ''.join([choice(printable[:62]) for x in range(26)])
    print A[:4]
    msg = 'ASIS needs proof of work to start the ' + _taskname + ' challenge.\n' + _hash.upper() + '(X + "%s").hexdigest() = "%s...",\nX is an alphanumeric string and |X| = 4\nEnter X: ' % (A[4:], sha512(A).hexdigest()[:32])
    client.send(msg)
    X = client.recv(_bufsize).strip()
    if sha256(X + A[4:]).hexdigest() == sha256(A).hexdigest():
        client.settimeout(_timeout)
        client.send('Good work, Let\'s Go!' + '\n')
        nbit = 1024
        params = getParams(nbit)
        N, g, k = params
        email = 'admin@asis-ctf.ir'
        client.send('Please login as "admin@asis-ctf.ir" and get the flag:' + '\n')
        client.send('Sever is generating the parameters ...' + '\n')
        client.send('params = (N, g, k) = ' + str(params) + '\n')
        
        salt = urandom(32)
        
        N, g, _ = params
        x = Hash(salt, email, password)
        verifier = pow(g, x, N)
                
    	while True:
            try:
                client.send('Send the email address and the public random positive value A seperated by "," as "email, A": ' + '\n')
                ans = client.recv(_bufsize).strip()
                print ans
                try:
                    email, A = ans.split(',')
                    A = int(A)
                    assert (A != 0 and A != N), client.send('Are you kidding me?! :P' + '\n')
                    assert email == 'admin@asis-ctf.ir', client.send('You should login as admin@asis-ctf.ir' + '\n')
                    b = getRandomRange(1, N)
                    B = (k * verifier + pow(g, b, N)) % N
                
                    client.send('(salt,  public_ephemeral) = (%s, %d) \n' % (salt.encode('base64')[:-1], B))
               
                    u = Hash(A, B)
                                        
                    client.send('Send the session key: ' + '\n')
                    K_client = client.recv(_bufsize).strip()                    
                    assert K_client.isdigit(), client.send('Please send a valid positive integer as session key.' + '\n')
                    K_client = int(K_client)
                
                    S_s = pow(A * pow(verifier, u, N), b, N)
                    K_server = Hash(S_s)        
                    
                    client.send('Send a POC of session key: ' + '\n')
                    M_client = client.recv(_bufsize).strip()
                    
                    
                    assert M_client.isdigit(), client.send('Please send valid positive integer as POC.' + '\n')
                    M_client = int(M_client)
                    
                    assert (K_server == K_client), client.send('The session key is not correct!' + '\n')    
                    assert (M_client == Hash(Hash(N) ^ Hash(g), Hash(email), salt, A, B, K_client)), client.send('The POC is not correct!' + '\n')
                   
                    M_server = Hash(A, M_client, K_server) # TODO: check server POC in clinet side

                    client.send('Great, you got the flag: ' + flag + '\n')
                    client.close()
                    break
                                        
                except:
                    client.send('Provided input is not valid.' + '\n')
                    client.send('Quiting ...' + '\n')
                    client.close()
                    break
 
            except socket.timeout:
                client.send('Timeout! Plase send faster ... \n')
                client.close()
                break
    else:
        client.send('Sorry, Bad proof of work! \n')
        client.close()


while True:
    client, addr = _socket.accept()
    start_new_thread(clientThread ,(client,))
s.close()