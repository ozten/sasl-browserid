# SASL BROWSER-ID Design Doc #

This proposal outlines a [SASL mechanism](http://tools.ietf.org/html/rfc2222) 
for authenticating via [BrowserID](https://browserid.org).

## Flow ##
### First Time ###
C: 

### During Current Session ###
C: session-token
S: checks TTL on session-token
S: sets userid and auth to email address
S: OK BROWSER-ID authentication successful


### During Stale Session with Valid Assertion ###
C: session-token
S: checks TTL on session-token
S: Issues assertion/audience challange
C: gets browserid assertion
C: sends assertion and audience
S: verifies assertion via browserid.org
S: generates session-token and creates session
S: Issues session-token challange
C: MAY record session-token for future use
S: sets userid and auth to email address
S: OK BROWSER-ID authentication successful

### Invalid Assertin ###
C: sends invalid assertion/audience pair
S: verifies assertion via browserid.org
S: NO BROWSER-ID authentication failed
