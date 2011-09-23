#!/usr/bin/env python
"""
Functional Test Suite.

For speed, these tests *should* be run outside of the Vagrant VM.
They *may* be run from within the VM.

They exercise the high level functions of the C plugin through OpenLDAP and
Python.
"""
import unittest

import ldap
from ldap.sasl import sasl, CB_USER, CB_AUTHNAME
import MySQLdb

import config


class browserid(sasl):
    """This class handles SASL client input names for
       BROWSER-ID authentication."""

    def __init__(self, assertion, audience):
        auth_dict = {CB_USER:assertion,
                     CB_AUTHNAME: audience}
        sasl.__init__(self, auth_dict, 'BROWSER-ID')


def insert_session_row(cursor, assertion, email):
    cursor.execute("""INSERT INTO browserid_session (digest, email)
                      VALUES (MD5(%(assertion)s), %(email)s)""",
                   dict(assertion=assertion, email=email))


class NormalUsageTestCase(unittest.TestCase):
    def setUp(self):
        # MySQL init
        params = dict(user=config.MYSQL_USER,
                      db=config.MYSQL_DB_NAME,
                      passwd=config.MYSQL_PASSWORD,
                      host=config.MYSQL_HOST,
                      port=config.MYSQL_PORT)
        # We can connect, right?
        self.db_conn = MySQLdb.connect(**params)

        cursor = self.db_conn.cursor()

        # Table exists? cleanup from prior runs
        cursor.execute('DELETE FROM browserid_session')
        cursor.close()

        # OpenLDAP init
        self.ldap_conn = ldap.initialize(config.LDAP_URI)

    def tearDown(self):
        self.db_conn.close()
        self.ldap_conn.unbind_s()

    def test_cached_assertion(self):
        assertion = '32lj432j4.some.really.long.string.23k4j23l4j'
        email = 'test@home.net'
        audience = 'example.com'
        cur = self.db_conn.cursor()
        try:
            insert_session_row(cur, assertion, email)
            #self.assertTrue(True)
        except Exception, e:
            raise e
        finally:
            cur.close()

        sasl_creds = browserid(assertion, audience)
        self.ldap_conn.sasl_interactive_bind_s("", sasl_creds)

        expected_dn = "dn:uid=%s,cn=browser-id,cn=auth" % email
        self.assertEqual(expected_dn, self.ldap_conn.whoami_s())

    def test_bad_assertion_no_auth(self):
        assertion = '32lj432j4.an.unknown.assertion.23k4j23l4j'
        audience = 'example.com'

        sasl_creds = browserid(assertion, audience)
        self.assertRaises(ldap.INVALID_CREDENTIALS, lambda:\
            self.ldap_conn.sasl_interactive_bind_s("", sasl_creds))

    def test_bad_assertion_empty_string(self):
        assertion = ''
        audience = ''

        sasl_creds = browserid(assertion, audience)
        self.assertRaises(ldap.INVALID_CREDENTIALS, lambda:\
            self.ldap_conn.sasl_interactive_bind_s("", sasl_creds))

    def test_bad_assertion_buffer_overflow_assertion(self):
        assertion = ''.join(map(str, range(400)))
        audience = 'example.com'

        sasl_creds = browserid(assertion, audience)
        self.assertRaises(ldap.INVALID_CREDENTIALS, lambda:\
            self.ldap_conn.sasl_interactive_bind_s("", sasl_creds))

    def test_bad_assertion_buffer_overflow_audience(self):
        assertion = 'l2k3j4kj324l2k3jlk.2l3j32.lkj324l32kj4'
        audience = ''.join(map(str, range(400)))

        sasl_creds = browserid(assertion, audience)
        self.assertRaises(ldap.INVALID_CREDENTIALS, lambda:\
            self.ldap_conn.sasl_interactive_bind_s("", sasl_creds))


if __name__ == '__main__':
    unittest.main()
