import sys

import ldap

from ldap.sasl import sasl, CB_USER, CB_AUTHNAME

class browserid(sasl):
    """This class handles SASL BROWSER-ID authentication."""

    def __init__(self, assertion, audience):
        auth_dict = {CB_USER:assertion,
                     CB_AUTHNAME: audience}
        sasl.__init__(self, auth_dict, 'BROWSER-ID')

    #def callback(self,cb_id,challenge,prompt,defresult):
    #    print("id=%d, challenge=%s, prompt=%s, defresult=%s" % (cb_id,challenge,prompt,defresult))
    #    return sasl.callback(self,cb_id,challenge,prompt,defresult)



def do_login(assertion):
    conn = ldap.initialize('ldap://:1389/')
    sasl_creds = browserid(assertion, 'localhost:8001')
    print repr(conn.sasl_interactive_bind_s("", sasl_creds))
    #print repr(conn.bind_s('uniqueIdentifier=7bad69771f,ou=people,dc=mozillians,dc=org', 'asdfasdf'))
    print 'login success'
    my_dn = conn.whoami_s()
    print 'whoami? %s' % repr(my_dn)
    rs = conn.search_s('ou=people,dc=mozillians,dc=org',
                       ldap.SCOPE_SUBTREE, 
                       '(uid=*1@*)', ['displayName', 'mail'])
    for dn, result in rs:
        print '%s %s' % (dn, repr(result))

if __name__ == '__main__':
    """
vagrant@lucid32:~/sasl-browserid$ python whoami.py $A
0
login success
vagrant@lucid32:~/sasl-browserid$ python whoami.py $A
0
login success
whoami? 'dn:uniqueIdentifier=7bad69771f,ou=people,dc=mozillians,dc=org'
[('uniqueIdentifier=7f3a67u000001,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000001']}), ('uniqueIdentifier=7f3a67u000011,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000011']}), ('uniqueIdentifier=7f3a67u000021,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000021']}), ('uniqueIdentifier=7f3a67u000031,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000031']}), ('uniqueIdentifier=7f3a67u000041,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000041']}), ('uniqueIdentifier=7f3a67u000051,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000051']}), ('uniqueIdentifier=7f3a67u000061,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000061']}), ('uniqueIdentifier=7f3a67u000071,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000071']}), ('uniqueIdentifier=7f3a67u000081,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000081']}), ('uniqueIdentifier=7f3a67u000091,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000091']})]


whoami? dn:uid=unknown@example.com,cn=browser-id,cn=auth
[('uniqueIdentifier=7f3a67u000001,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000001']}), ('uniqueIdentifier=7f3a67u000011,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000011']}), ('uniqueIdentifier=7f3a67u000021,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000021']}), ('uniqueIdentifier=7f3a67u000031,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000031']}), ('uniqueIdentifier=7f3a67u000041,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000041']}), ('uniqueIdentifier=7f3a67u000051,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000051']}), ('uniqueIdentifier=7f3a67u000061,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000061']}), ('uniqueIdentifier=7f3a67u000071,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000071']}), ('uniqueIdentifier=7f3a67u000081,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000081']}), ('uniqueIdentifier=7f3a67u000091,ou=people,dc=mozillians,dc=org', {'uniqueIdentifier': ['7f3a67u000091']})]

    Who am I tells us one of two things...
    * I have an account (uniqueIdentifier)
    * I don't have an account (uid=unknown@example.com)
    """
    if (len(sys.argv) > 1):
        do_login(sys.argv[1])
        sys.exit(0)
    else:
        print('Usage: %s some-long-assertion-string from http://localhost:8001/browserid_debug.html' % sys.argv[0])
        sys.exit(1)
