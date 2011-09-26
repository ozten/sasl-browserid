# Tests #

The easiest way to run the tests is from within a Vagrant VM.

## Dependencies ##

These tests depend on the following:

* Apache - fakes browser verification services
* MySQL - plugin session store
* OpenLDAP - SASL enabled LDAP directory server
* Python - Tests sasl-browserid directly and indirectly.
* SASL2-bin - Test programs and utilities from Cyrus SASL

Each of these must be setup and running based on ../configs/

## Running Tests ##

Setup config (edit as needed).

    cp test/config.py-dist test/config.py

Run the following command:

    sudo python test/unit_privileged_test_suite.py
    python test/functional_test.py
    