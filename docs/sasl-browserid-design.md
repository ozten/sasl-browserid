# SASL BROWSER-ID Design Doc #

This proposal outlines a [SASL mechanism](http://tools.ietf.org/html/rfc2222) 
for authenticating via [BrowserID](https://browserid.org).

TODO write this up in client / server dialog for RFC.

## Terminology ##

Assertion - A BrowserID encrypted token from a user's browser stating
that they own a certain email address.

Audience - A hostname and optionally a port number which requested the assertion. Examples: example.com, foo.example.com:8001

Sessions - A web oriented use of this auth mechanism can configure 
the mechanism to maintain a session state where Assertion verification is 
cached.

## Flow ##
### First Time Valid Assertion ###
Client sends assertionNULLaudience.
Server receives assertionNULLaudience.
Server MAY check a session via MD5 hash of assertion
Server sees session cache miss.
Server uses a GET request to browserid.org verfication web service.
Server parses response as JSON.
Server sees state is "okay" and email is "jane@example.com".
Server MAY creat a session storing MD5 hash of assertion, email, and a modified timestamp.
Server sets authid and authidz to email
Server responds auth successful

### Second Request, Using Session ###
This assumes a current session

Client sends assertionNULLaudience.
Server receives assertionNULLaudience.
Server checks a session via MD5 hash of assertion
Server sees session cache hit.
Server loads email from session from MD5 hash.
Server updates the modified time of the session by MD5 hash.
Server sets authid and authidz to email
Server responds auth successful

### Invalid Assertin ###
Client sends assertionNULLaudience.
Server receives assertionNULLaudience.
Server checks a session via MD5 hash of assertion
Server sees session cache miss.
Server uses a GET request to browserid.org verfication web service.
Server parses response as JSON.
Server sees state is "failure".
Server responds auth failure

