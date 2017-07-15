#!/usr/bin/env
# -*- coding: utf-8 -*-

# Copyright (c) 2016 zer0.de aka V1p3r 4 OWC
# All rights reserved.

# This is Version 0.5

# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE

#
# The basic daemon function created by
# - Ben Timby - btimby <at> gmail.com
# - Giampaolo Rodola' - g.rodola <at> gmail.co
#

import errno
import os
import sys
import optparse
import atexit
import signal
import time
import logging
from pip.cmdoptions import log_file

#Fix support python 3
try:
    import ConfigParser
except ImportError:
    import configparser

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import ThreadedFTPServer
from hashlib import md5



#OS Check 4 FS handler
# 4 unix use
if os.name == "posix":
    from pyftpdlib.filesystems import UnixFilesystem
    Unix_FS = UnixFilesystem

#globals
PID_FILE = "OWC-FTPd.pid"
CONFIG_FILE = "config.ini"
LOG_FILE = "ftpd.log"
WORKDIR = os.getcwd()
UMASK = 0
HOST = ""
PORT = 1337
user1 = ""
user2 = ""


#
# 
# Code Start 
#
#

class Login_MD5(DummyAuthorizer):

    def validate_authentication(self, username, password, handler):
        if sys.version_info >= (3, 0):
            password = md5(password.encode('latin1'))
        hash = md5(password).hexdigest()
        try:
            if self.user_table[username]['pwd'] != hash:
                raise KeyError
        except KeyError:
            raise AuthenticationFailed

#error handel def
def _strerror(err):
        if isinstance(err, EnvironmentError):
            try:
                return os.strerror(err.errno)
            except AttributeError:
                # not available on PythonCE
                if not hasattr(os, 'strerror'):
                    return err.strerror
                raise
        else:
            return str(err)

#SITE COMMANDS

#SITE EXEC
proto_cmds = TLS_FTPHandler.proto_cmds.copy()
proto_cmds.update(
    {'SITE EXEC': dict(perm='m', auth=True, arg=True, help='Syntax: SITE <SP> EXEC <SP> app (Execute a file on CMD/Shell).')}
)

#SITE ADDUSER USERNAME PASSWORT HOME PRIVS
proto_cmds.update(
    {'SITE ADDUSER': dict(perm='m', auth=True, arg=True, help='Syntax: SITE <SP> ADDUSER USERNAME PASSWORT(MD5) HOME PRIVS <SP>(Set an temp. User).')}
)

# more commands...


class siteadd(TLS_FTPHandler):
    proto_cmds = proto_cmds


    def ftp_SITE_EXEC(self, line):
        """Execute a file on CMD/Shell"""
        try:
            subprocess.call([line])
        except OSError as err:
             why = _strerror(err)
             self.respond('550 %s.' % why)

    def ftp_SITE_ADDUSER(self,arg):
        """Adding a User on the fly/temp"""
        user,passwd,home,priv = arg.split(' ')
        user = user.rpartition("/")
        try:       
            self.authorizer.add_user(str(user[2]), md5(str(passwd)).hexdigest(), str(home), perm=str(priv))
            self.respond("220 User: '%s' with pass: '%s' home: '%s' and priv='%s' succesfull added." % (user[2],passwd,home,priv) )
            #add user 2 ini
            #todo
        except OSError as err:
            why = _strerror(err)
            self.respond('550 %s.' % why)

#Daemon Started her

def pid_exists(pid):
    """Return True if a process with the given PID is currently running."""
    try:
        os.kill(pid, 0)
    except OSError as err:
        return err.errno == errno.EPERM
    else:
        return True

def get_pid():
    """Return the PID saved in the pid file if possible, else None."""
    global PID_FILE
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except IOError as err:
        if err.errno != errno.ENOENT:
            raise

def stop():
    """Keep attempting to stop the daemon for 5 seconds, first using SIGTERM, then using SIGKILL."""
    global HOST,PORT
    config = ConfigParser.RawConfigParser()
    config.read(CONFIG_FILE)
    LOG_FILE = config.get('FILES','Logfile')
    
    
    pid = get_pid()
    if not pid or not pid_exists(pid):
        sys.exit("daemon not running")
    sig = signal.SIGTERM
    i = 0
    while True:
        sys.stdout.write('.')
        sys.stdout.flush()
        try:
            os.kill(pid, sig)
        except OSError as err:
            if err.errno == errno.ESRCH:
                print("\nstopped (pid %s)" % pid)
                os.remove(PID_FILE)
                print("\nPID '%s' removed!" % PID_FILE)
                l = open(LOG_FILE,'a')
                l.write("INFO:pyftpdlib:>>> stopping FTP server on %s:%s <<<\n" % (HOST,PORT) )
                l.close()
                return
            else:
                raise
        i += 1
        if i == 25:
            sig = signal.SIGKILL
        elif i == 50:
            sys.exit("\ncould not kill daemon (pid %s)" % pid)
        time.sleep(0.1)

def status():
    """Print daemon status and exit."""
    pid = get_pid()
    if not pid or not pid_exists(pid):
        print("daemon not running")
    else:
        print("daemon running with pid %s" % pid)
    sys.exit(0)

def get_server():
    global HOST,PORT,CONFIG_FILE,LOG_FILE
    """Return a pre-configured FTP server instance."""
    #get Vars
    config = ConfigParser.RawConfigParser()
    config.read(CONFIG_FILE)
   
    # get user
    try:
        user = config.get('User=0', 'User')
        pw =  config.get('User=0', 'Passwort')
        home = config.get('User=0', 'HomeDir')
        perms = config.get('User=0', 'Permission')
    except:
        print("No User Added in settings.ini - Stop")


    try:
        user1 = config.get('User=1', 'User')
        pw1 =  config.get('User=1', 'Passwort')
        home1 = config.get('User=1', 'HomeDir')
        perms1 = config.get('User=1', 'Permission')
    except:
        pass

    try:
        user2 = config.get('User=2', 'User')
        pw2 =  config.get('User=2', 'Passwort')
        home2 = config.get('User=2', 'HomeDir')
        perms2 = config.get('User=2', 'Permission')
    except:
        pass

    HOST = config.get('SERVER', 'IP')
    PORT = config.getint('SERVER', 'Port')
    LOG_FILE = config.get('FILES','Logfile')
    CERTFILE = config.get('FILES','Certfile')
    SSL_CONTROL = config.getboolean('MISC','SSLControl')
    SSL_DATA = config.getboolean('MISC','SSLData')
    MAX_IP = config.getint('MISC','Max_Logins')
    MAX_CON = config.getint('MISC','Max_Con')
    LoginMessage = config.get('MISC', 'LoginMessage')
    
    #Add User
    authorizer = Login_MD5()
    authorizer.add_user(user, pw, home, perm=perms)

    if user1 != "":
        authorizer.add_user(user1, pw1, home1, perm=perms1)
    if user2 != "":
        authorizer.add_user(user2, pw2, home2, perm=perms2)
    
    # using SSL
    handler = siteadd
    handler.certfile = CERTFILE
    handler.authorizer = authorizer
    
    #requires SSL for both control and data channel
    handler.tls_control_required = SSL_CONTROL
    handler.tls_data_required = SSL_DATA

    # FXP on/off :default is off
    handler.permit_foreign_addresses = True 

    # Logging to file: logging.INFO is normal logging.DEBUG is for bot using like eggdrop or something to show in a IRC Chan.
    logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG)


    # Instantiate FTP server class and listen1
    address = (HOST, PORT)
    server = ThreadedFTPServer(address, handler)

    # set a limit for connections
    server.max_cons = MAX_CON
    server.max_cons_per_ip = MAX_IP
    
    #unix Filesystem?
    if Unix_FS in globals():
        handler.abstracted_fs = Unix_FS
    
    # Login Message
    handler.banner = LoginMessage
    return server

def daemonize():
    """A wrapper around python-daemonize context manager."""
    global HOST,PORT,PID_FILE
    def _daemonize():
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)

        # decouple from parent environment
        os.chdir(WORKDIR)
        os.setsid()
        os.umask(0)

        # do second fork
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(LOG_FILE)
        so = open(LOG_FILE, 'a+')
        se = open(LOG_FILE, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        pid = str(os.getpid())
        with open(PID_FILE, 'w') as f:
            f.write("%s\n" % pid)
        atexit.register(lambda: os.remove(PID_FILE))

    pid = get_pid()
    if pid and pid_exists(pid):
        sys.exit('daemon already running (pid %s)' % pid)

    # instance FTPd before daemonizing, so that in case of problems we
    # get an exception here and exit immediately
    server = get_server()
    print("\nServer is starting ... please wait a sek.")
    print("\nStarting with '%s' Listen on: '%s:%s'" % (CONFIG_FILE , HOST , PORT))
    _daemonize()
    server.serve_forever()

def main():
    global PID_FILE, CONFIG_FILE
    DESC = "FTPd written in Python\n" \
            "copyright by zer0.de for OWC 2016\n\n"
    
    USAGE = "python [-p PIDFILE] [-c CONFIG]\n\n" \
            "Commands:\n  - start\n  - stop\n  - restart\n - status"
            
    parser = optparse.OptionParser(description=DESC,usage=USAGE)
    
    parser.add_option('-c', '--configfile', dest='configfile', default=CONFIG_FILE, help='the config file location')
    parser.add_option('-p', '--pidfile', dest='pidfile', default=PID_FILE, help='file to store/retreive daemon pid')
    
    options, args = parser.parse_args()

    if options.pidfile:
        PID_FILE = options.pidfile
    if options.configfile:
        if os.path.exists(options.configfile):
            CONFIG_FILE = options.configfile
        else:
            sys.exit('Config "%s" doesnt found, please check the path/name' % options.configfile)

    if not args:
        #print help
        sys.exit("FTPd written in Python\ncopyright by zer0.de for OWC 2016\n\n" \
            "Usage: python [-p PIDFILE] [-l LOGFILE]\n\n" \
              "    Commands:\n" \
              "    - start\n" \
              "    - stop\n" \
              "    - status\n\n" \
              "    Options:\n" \
              "    -h, --help\n\t" \
              "        show this help message and exit\n" \
              "    -l LOGFILE, --logfile=LOGFILE\n\t" \
              "        the log file location\n" \
              "    -p PIDFILE, --pidfile=PIDFILE\n\t" \
              "        file to store/retreive daemon pid\n")
    else:
        if len(args) != 1:
            sys.exit('too many commands')
        elif args[0] == 'start':
            daemonize()
        elif args[0] == 'stop':
            stop()
        elif args[0] == 'restart':
            try:
                stop()
            finally:
                daemonize()
        elif args[0] == 'status':
            status()
        else:
            sys.exit('invalid command')

if __name__ == '__main__':
    sys.exit(main())
