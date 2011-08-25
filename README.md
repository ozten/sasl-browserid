# SASL BrowserID #
SASL BrowserID is a new [SASL mechanism](http://asg.web.cmu.edu/sasl/sasl-library.html).

Who da what?

SASL stands for Simple Authentication and Secruity Layer. It is a standardized API for re-using authentication mechanisms.

[BrowserID](https://browserid.org) is an open web standard for providing a verified email address to websites for authentication.

This project aims to provide a plugin written in C for the popular CMU Cyrus SASL API Implementation. This can be used by:

* OpenLDAP directory server
* Email servers (CMU, postfix, etc)
* ??? Tell us other use cases!

## Status ##
Not ready for prime-time.

This codebase is roughly the happy case, but needs much <3.

We'd love your help!

* C Hackers
* Make Masters
* Cross-platform Funsters

## Requirements ##
This plugin is under development on i686 Ubuntu 10.04 with:

* Cyrus SASL 2.1.23
* OpenLDAP 2.4.23
* libcurl
* [yajl](https://github.com/lloyd/yajl) 2.0.1
* MySQL client libraries for C

### Ubuntu Tips ###
1) sudo aptitude install ruby cmake libcurl libcurl-dev libmysqlclient-dev

2) Compile (yajl)[https://lloyd.github.com/yajl/]

We want yajl 2.0.1 or greater, which most distros haven't packaged.

    wget http://github.com/lloyd/yajl/tarball/2.0.1 -O yajl-2.0.1.tar.gz
    tar zxvf yajl-2.0.1.tar.gz
    cd lloyd-yajl-f4b2b1a
    ./configure
    sudo make install

## Install SASL-BrowserID ##

Assuming you have the requirements installed, you can:

    configure
    make
    sudo make install

This will create libbrowserid plugins under /usr/lib/sasl2

Details can be found in the INSTALL doc or 

    ./configure --help

## Sanity Tests ##

The following are ways to test this plugin.

For all of the following tests, it's best to

    sudo tail -f /var/log/auth.log

When prompted for an Assertion and Audience, use browserid_debug.html and a local webserver. Example:

    Assertion: eyJhbGci...blah...blah...2mtVg68723mlBPAQds_bPsG8mllYg
    Audience: localhost:8001

There are 3 ways to test, pluginviewer, slapd, and sample program.

### pluginviewer ###

    sudo saslpluginviewer

Do you see BROWSER-ID in the list of SASL client and server mechanisms?

### OpenLDAP (slapd) ###

    sudo cp configs/slapd.conf /usr/lib/sasl2
    ldapwhoami -Y BROWSER-ID -I

### Sample client and server ###
If you've compiled SASL's sample/client and sample/server programs...

    sudo cp configs/sample.conf /usr/lib/sasl2
    cd ${SASL_SRC}
    ./sample/server -p 8089 -s testing -m BROWSER-ID
    ./sample/client -p 8089 -s testing -m BROWSER-ID localhost


## License ##
plugins/plugin_common.c and plugins/plugin_common.h are copied from (CMU's Cyrus SASL distribution)[http://ftp.andrew.cmu.edu/pub/cyrus-mail/].
They are copywrite CMU and licensed per file. See files for details.

The rest of this codebase is original and Copywrite Mozilla Corporation 2011.
A License is TBD.

We'll pick a license that works well with Cyrus SASL distributions and balances other factors.