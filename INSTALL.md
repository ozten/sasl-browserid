## Installation ##
It's early days. I realize this makes baby narwhals weep.

0. Get the source to Cyrus SASL and make sure you can build it.

1. Apply sasl-Makefile-diff.txt patch which adds browserid to the build.

2. Copy plugins/browserid*.c into your SASL source plugins directory.

3. libcurl and yajc aren't hooked into the Makefile, so do this manually:

    cd plugins && gcc -DHAVE_CONFIG_H -I ../../mozillians/yajl/build/yajl-2.0.3/include -I. -I. -I.. -I../include -I../lib -I../sasldb -I../include -Wall -W -g -O2 -MT browserid.lo -MD -MP -MF .deps/browserid.Tpo -c browserid.c  -fPIC -DPIC -o browserid.lo; cd .. 

4. Compile and Copy shared libraries

    make && make install && sudo cp  /home/vagrant/local/sasl2/lib/sasl2/*browser* /usr/lib/sasl2/

Assuming you had prefixed your original configure with /home/vagarnt/local/sasl2

5. Restart any client or server applications which use SASL

    sudo cp configs/*.conf /usr/lib/sasl2/
    sudo tail -f /var/log/auth.log
    slapd -d 64 -f slapd.conf -h 'ldap://:1389' -n vagrant-slapd

6. Use /sbin/saslpluginviewer to test that BROWSERID is listed as an auth mechanism

This may be called pluginviewer, changes per OS.

7. Use a client and tell it to use SASL with BROWSERID

    ldapwhoami -Y BROWSERID -H ldap://:1389/ -I

8. When prompted for an Assertion and Audience, use browserid_debug.html and a local webserver. Example:

    Assertion: eyJhbGci...blah...blah...2mtVg68723mlBPAQds_bPsG8mllYg
    Audience: localhost:8001

Watch auth.log and slapd's output to see what works and what doesn't.

9. You can use SASL's sample client and server too.