import ldap
import os
import shutil
import time
import glob
from signal import SIGTERM
from subprocess import Popen, call

import config as conf


def reset_db():
    # don't remove subdirectory so we keep permissions
    for f in glob.glob('%s/*' % conf.SLAPD_DB_PATH):
        os.remove(f)

    # load data
    users = "%s/users.ldif" % conf.SLAPD_CONFIG
    args = [
        'ldapmodify', '-x',
        '-H', conf.LDAP_URI,
        '-D', 'cn=root,dc=example,dc=com',
        '-w', 'pass',
        '-a', '-f', users
    ]
    call(args)


def restart_slapd():
    kill_slapd()
    start_slapd()

def kill_slapd():
    pidfile = conf.SLAPD_PID
    if not os.path.exists(pidfile):
      return

    with open(pidfile, 'r') as f:
        pid = int(f.readline().strip())
        try:  
            os.kill(pid, SIGTERM)
        except:
            pass
        os.remove(pidfile)

def start_slapd():
    config = "%s/slapd.conf" % conf.SLAPD_CONFIG
    # run under openldap account
    # TODO: integrate with /etc/init.d/slapd
    args = ['/usr/sbin/slapd',
            '-h', conf.LDAP_URI,
            '-f', config,
            '-u', 'openldap',
            '-g', 'openldap']

    call(args)

    while not os.path.exists(conf.SLAPD_PID):
      print "slapd not started! Sleeping 1 second"
      time.sleep(1)

def wait_for_jane():
    """Function attempts to detect when jane@doe.com is in 
       the LDAP directory. Waits until the directory has been
       populated, then returns."""
    while True:
        try:
            conn = ldap.initialize(conf.LDAP_URI)
            conn.bind(conf.LDAP_ROOT_DN, conf.LDAP_ROOT_PASS)
            conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, '(uid=jane@doe.com)')
            break
        except ldap.NO_SUCH_OBJECT:
            print "still loading"
            continue

if __name__ == '__main__':
    restart_slapd()
    reset_db()
