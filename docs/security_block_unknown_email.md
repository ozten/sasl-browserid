# Block Unknown Email #
Another important security note, is that BROWSER-ID will
set authid and authidz to a valid email address. It 
does not (and cannot) confirm that this email address
is meaningful in your system!

Any clients and servers that you BROWSER-ID enable MUST
do this validation. Below are some common cases...

## Worst Case ##
Let's say you have a resource 'keys-to-the-kingdom'. Before
you depended on username and password. Calling 'get-keys-to-the-kingdom'
would fail if a valid username/password combo were entered.

You add SASL BROWSER-ID. Calling 'get-keys-to-the-kingdom' always 
successeds as long as the user submitted a valid verify email assertion
and audience. Even if 'unknown@example.com' should not have been allowed
access to 'keys-to-the-kingdom'.

How do we fix this?

Basically, we need to make sure that we've been authenticated as a 
valid user. How this is done will vary system by system.

Generically:
* Enforce ACL in your configuration
* Enforce strict mapping of email address into valid accounts
* Discover email address and make sure it's known
* Have a 'new user' registration path for unknown users

So with our keys-to-the-kingdom approach, we could query a database to
make sure the email address exists in our user table.

The following are specific SASL enabled services:

## OpenLDAP ##
Make sure your slapd.conf has ACL that restrict access
to known users. Have a strict mapping for authentication identities.

### Server Side ###

Example slapd.conf snippets:

    authz-regexp
        uid=([^,]*),cn=browser-id,cn=auth
        uid=$1,ou=people,dc=example,dc=com

    authz-regexp
        uid=([^,]*),cn=browser-id,cn=auth
        ldap:///ou=people,dc=example,dc=com??one?(mail=$1)


### Client Side ###

In code, use ldap's whoami function and ensure that the DN does not 
contain `cn=browser-id`.

If whoami is unavailable, good ACL and a ACL test suite are critical.

### Testing Notes ###
Make sure unknown email addresses fail when trying to search/add/modify/delete.

Make sure multiple records with the email address cause an auth failure.