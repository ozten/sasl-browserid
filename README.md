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
* libcurl4-dev
* [yajl](https://github.com/lloyd/yajl)

## License ##
TBD. Copywrite Mozilla Corporation 2011.

We'll pick a license that works well with Cyrus SASL distributions and balances other factors.