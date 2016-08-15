## Supplemental to README.Mark

Provides Active Directory authentication, with the capability of domain administrators
to make changes to AD through a self-built web application. This does not involve
hard-coding administrative credentials. All that's needed is a single read-only LDAP
user.

My changes to the original library make this fairly alpha, particularly given what I'm
doing to store an encrypted copy of the user's credentials, for convenient reuse.

## Environment notes

- The library makes use of the PHP function `ldap_modify_batch()`, which is only available
in 5.4 >= 5.4.26, PHP 5.5 >= 5.5.10, PHP 5.6 >= 5.6.0 and PHP 7. Ubuntu 14.04's max
version (at the time of writing) is PHP 5.5.9 so Ubuntu 14 does not have this function by
default. You could use Ondrej Surý's [PPA for PHP 5.5](https://launchpad.net/~ondrej/+archive/php5  )
to overcome this.
- For obvious reasons, this requires the PHP LDAP module.
- Your domain's root certificate needs to be installed on the web server, for LDAPS to
work. Alternatively, you can set TLS_REQCERT to "never" in your ldap.conf (not recommended).
