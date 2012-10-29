#!/usr/bin/python
# coding: UTF-8
# HTTP Proxy for xntalk
# and a Man In The Mid attacking tool
# coded by YeahO_O 2012.7.12

import socket, select, ssl
import logging, re, time, os, threading

# Configuation goes here ==============
PORT = 8080
logging.root.setLevel(logging.INFO)
# End of Configuation =================

strSend = '\n\n\n[ local ] ' + '>' * 10 + '=' * 10 + ' [        ]\n'
strRecv = '\n\n\n[       ] ' + '=' * 10 + '<' * 10 + ' [ remote ]\n'
sockSize = 4096
myCertFile = 'MyRenCert.pem'

def parseHeader(h):
    r = re.search(r'CONNECT (?P<host>[0-9.]+):(?P<port>[0-9]+) HTTP/1.0', h)
    if not r: return None
    return (r.group('host'),int(r.group('port')))
    
class clientThread(threading.Thread):
    def __init__(self, clientSocket):
        self.socket = clientSocket
        threading.Thread.__init__(self)
    
    def handleTCP(self, local, remote):
        last = None
        fn = os.path.join('capture', '%s.log'%(time.strftime('%Y%m%d-%H%M%S')))
        
        try:
            f = open(fn, 'w')
        except IOError, e:
            logging.error('Fail to open logging file %s'%(fn))
            return 
        
        logging.info('Log file opened at %s.'%(fn))
        fdset = [local, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            logging.debug('Handling...')
            if local in r:
                logging.debug('[Readable] local')
                k = local.recv(sockSize)
                logging.debug(k.__repr__())
                if last != local:
                    last = local
                    f.write(strSend)
                f.write(k)
                if remote.send(k) <= 0: break
                
                # End of stream check
                if k == '</stream:stream>':
                    logging.info('XMPP Stream Ends.')
                    break
            if remote in r:
                logging.debug('[Readable] remote')
                k = remote.recv(sockSize)
                logging.debug(k.__repr__())
                if last != remote:
                    last = remote
                    f.write(strRecv)
                f.write(k)
                if local.send(k) <= 0: break
                
                # TLS negotiation check
                # Client: <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>
                # Server: <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
                # Then, TLS negotiation starts.
                if k.startswith('<proceed'):
                    logging.info('TLS Negotiation starts.')
                    # Remote
                    remote = ssl.wrap_socket(remote,
                        ssl_version = ssl.PROTOCOL_TLSv1,
                        do_handshake_on_connect = False)
                    remote.do_handshake()
                    logging.debug('Remote TLS Negotiation done.')
                    # Local
                    local = ssl.wrap_socket(local,
                        ssl_version = ssl.PROTOCOL_SSLv23,
                        keyfile = myCertFile,
                        certfile = myCertFile,
                        server_side = True,
                        do_handshake_on_connect = False)
                    local.do_handshake()
                    logging.debug('Local TLS Negotiation done.')
                    # The point where I am TRAPPED for several days
                    fdset = [local, remote]
                    logging.info('Stream reset.')
        f.close()
        local.close()
        remote.close()
        logging.info('Connection closed')
        
    def run(self):
        sock = self.socket
        h = sock.recv(sockSize)
        addr = parseHeader(h)
        if not addr:
            logging.error('Unknown header: \n%s'%(h))
            raise RuntimeError('Unknown header')
        logging.debug('Connecting to %s:%s...'%(addr))
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(addr)
        logging.debug('Connected.')
        sock.sendall('HTTP/1.0 200 Connection established\r\n\r\n\r\n')
        self.handleTCP(sock, remote)
    
def main():
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.bind(('', PORT))
    ss.listen(3)
    print 'HTTP Proxy for xntalk\n=====================\ncode by YeahO_O 2012.7.12\n'
    print 'USAGE\n=====\n人人桌面 登陆界面 -> [代理设置] -> [使用下面定义的代理]'
    print '主机：%s，端口：%d\n'%(socket.gethostbyname(socket.gethostname()), PORT)
    print 'All captured data will be saved at directory "captured"\n'
    print '**ONLY** XMPP stream will be captured, Rest API **CANNOT** be captured.'
    print 'because they will not be transmitted via this proxy.\n'
    while 1:
        (clientSocket, addr) = ss.accept()
        ct = clientThread(clientSocket)
        logging.info('Handling connection from %s:%d'%(addr))
        ct.start()
        
if __name__ == '__main__':
    main()
    