# dopenldap
dlang openldap simple binding

Minimal (connect to LDAP server, synchronous search and bind) bindig to openldap C library

Usage example

```
import openldap;
import std.stdio;
import std.format;
import std.string;
import std.experimental.logger;

void main() {
    globalLogLevel(LogLevel.info);
    int proto_version;

    auto ldap = LDAPConnection("ldap://ldap.forumsys.com");
    ldap.get_option(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
    if ( proto_version == 2) {
        proto_version = 3;
        ldap.set_option(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
        info("Switched to protocl version 3");
    }

    auto r = ldap.search_s("dc=example,dc=com",
        LDAP_SCOPE_SUBTREE, "(uid=%s)".format("einstein"));
    infof("Found dn: %s", r[0].dn);
    foreach(k,v; r[0].entry) {
        infof("%s = %s", k, v);
    }

    int b = ldap.bind_s(r[0].dn, "password");
    infof("Bind using 'password': %s", b==0?"OK":"Fail");
    ldap.unbind();
}
```
