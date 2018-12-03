#!/usr/bin/env python
# svwar.py - SIPvicious extension line scanner

__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
   Copyright (C) 2010  Sandro Gauci <sandro@enablesecurity.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from svhelper import __author__, __version__
__prog__ = 'svwar'

import socket
import select
import random
import logging
import time


class TakeASip:
    def __init__(self,host='localhost',bindingip='',externalip=None,localport=5060,port=5060,
                 method='REGISTER',guessmode=1,guessargs=None,selecttime=0.005,
                 sessionpath=None,compact=False,socktimeout=3,initialcheck=True,
                 disableack=False,maxlastrecvtime=15
                 ):
        from svhelper import dictionaryattack, numericbrute, packetcounter
        import logging
        self.log = logging.getLogger('TakeASip')
        self.maxlastrecvtime = maxlastrecvtime
        self.sessionpath = sessionpath
        self.dbsyncs = False
        self.disableack = disableack
        if self.sessionpath is not  None:
            self.resultauth = anydbm.open(os.path.join(self.sessionpath,'resultauth'),'c')
            try:
                self.resultauth.sync()
                self.dbsyncs = True
                self.log.info("Db does sync")
            except AttributeError:
                self.log.info("Db does not sync")
                pass
        else:
            self.resultauth = dict()
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.settimeout(socktimeout)
        self.bindingip = bindingip        
        self.localport = localport
        self.originallocalport = localport
        self.rlist = [self.sock]
        self.wlist = list()
        self.xlist = list()
        self.challenges = list()        
        self.realm = None
        self.dsthost,self.dstport = host,int(port)
        self.guessmode = guessmode
        self.guessargs = guessargs
        if self.guessmode == 1:
            self.usernamegen = numericbrute(*self.guessargs)            
        elif guessmode == 2:
            self.usernamegen = dictionaryattack(self.guessargs)
        self.selecttime = selecttime
        self.compact=compact
        self.nomore=False
        self.BADUSER=None
        self.method = method.upper()
        if self.sessionpath is not None:
            self.packetcount = packetcounter(50)
        self.initialcheck = initialcheck
        self.lastrecvtime = time.time()
        if externalip is None:
            self.log.debug("external ip was not set")
            if (self.bindingip != '0.0.0.0') and (len(self.bindingip) > 0):
                self.log.debug("but bindingip was set! we'll set it to the binding ip")
                self.externalip = self.bindingip
            else:
                try:
                    self.log.info("trying to get self ip .. might take a while")
                    self.externalip = socket.gethostbyname(socket.gethostname())
                except socket.error:
                    self.externalip = '127.0.0.1'
        else:
            self.log.debug("external ip was set")
            self.externalip = externalip


#   SIP response codes, also mapped to ISDN Q.931 disconnect causes.

    PROXYAUTHREQ = 'SIP/2.0 407 '
    AUTHREQ = 'SIP/2.0 401 '
    OKEY = 'SIP/2.0 200 '
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
    DECLINED = 'SIP/2.0 603 '
    INEXISTENTTRANSACTION = 'SIP/2.0 481'
    
    # Mapped to ISDN Q.931 codes - 88 (Incompatible destination), 95 (Invalid message), 111 (Protocol error)
    # If we get something like this, then most probably the remote device SIP stack has troubles with
    # understanding / parsing our messages (a.k.a. interopability problems).
    BADREQUEST = 'SIP/2.0 400 '
    
    # Mapped to ISDN Q.931 codes - 34 (No circuit available), 38 (Network out of order), 41 (Temporary failure),
    # 42 (Switching equipment congestion), 47 (Resource unavailable)
    # Should be handled in the very same way as SIP response code 404 - the prefix is not correct and we should
    # try with the next one.
    SERVICEUN = 'SIP/2.0 503 '
    
    def createRequest(self,m,username,auth=None,cid=None,cseq=1):
        from base64 import b64encode
        from svhelper import makeRequest
        from svhelper import createTag
        if cid is None:
            cid='%s' % str(random.getrandbits(32))
        branchunique = '%s' % random.getrandbits(32)
        localtag=createTag(username)
        contact = 'sip:%s@%s' % (username,self.dsthost)
        request = makeRequest(
                                m,
                                '"%s"<sip:%s@%s>' % (username,username,self.dsthost),
                                '"%s"<sip:%s@%s>' % (username,username,self.dsthost),
                                self.dsthost,
                                self.dstport,
                                cid,
                                self.externalip,
                                branchunique,
                                cseq,
                                auth,
                                localtag,
                                self.compact,
                                contact=contact,
                                localport=self.localport,
                                extension=username
                              )
        return request

    def getResponse(self):
        from svhelper import getNonce,getCredentials,getRealm,getCID,getTag        
        from base64 import b64decode
        from svhelper import parseHeader
        from svhelper import mysendto
        import re
        # we got stuff to read off the socket
        from socket import error as socketerror
        buff,srcaddr = self.sock.recvfrom(8192)
        try:
            extension = getTag(buff)
