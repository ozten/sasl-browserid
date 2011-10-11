import ldap
import os
import shutil
from subprocess import Popen, call

import config as conf


def reset_db():

    kill_slapd()

    shutil.rmtree(conf.SLAPD_DB_PATH)
    os.mkdir(conf.SLAPD_DB_PATH)

    start_slapd()

    # load data
    users = "%s/users.ldif" % conf.SLAPD_CONFIG
    args = [
        'ldapmodify', '-x',
        '-H', conf.LDAP_URI,
        '-D', 'cn=root,dc=example,dc=com',
        '-w', 'pass',
        '-a', '-f', users
    ]
    Popen(args)


def kill_slapd():
    try:

        f = open("%s/slapd.pid" % conf.SLAPD_CONFIG, 'r')
        pid = f.readline().rstrip()
        f.close()
        Popen(['kill', pid])
        os.remove("%s/slapd.pid" % conf.SLAPD_CONFIG)
        return True
    except Exception:
        return False

def start_slapd():
    config = "%s/slapd.conf" % conf.SLAPD_CONFIG
    call(['slapd', '-h', conf.LDAP_URI, '-f', config])

    while True:
        try:
            conn = ldap.initialize(conf.LDAP_URI)
            conn.bind('', '')
            break
        except ldap.SERVER_DOWN:
            #print "still starting up"
            continue

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
    reset_db()
