module openldap;
import std.format;
import std.string;
import core.sys.posix.sys.time;
import core.time;
import std.datetime;
import std.conv;
import std.typecons;
import std.c.stdlib;
import std.algorithm;
import std.experimental.logger;

struct berval {
    int             bv_len;
    char            *bv_val;
}
alias BerValue = berval;
struct ldapcontrol {
    char *          ldctl_oid;                      /* numericoid of control */
    berval          ldctl_value;            /* encoded value of control */
    char            ldctl_iscritical;       /* criticality */
};
alias LDAPControl = ldapcontrol;

extern (C) void ber_bvarray_free(berval *bvarray);
extern (C) void ber_bvfree(berval *bv);
extern (C) void  ldap_msgfree(void*);
extern (C) void ldap_memfree(void *);
extern (C) void ldap_value_free_len(berval**);
extern (C) void ldap_value_free(berval**);

extern (C) int ldap_get_option(void *ld, int option, void *outvalue);
extern (C) int ldap_set_option(void *ld, int option, const void *invalue);


extern (C) int   ldap_initialize(void**, const char*);
extern (C) char* ldap_err2string(int);
extern (C) void* ldap_first_entry(void *ld, void *chain );
extern (C) void* ldap_next_entry(void *ld, void *entry);
extern (C) char* ldap_get_dn(void* ld, void* entry);
extern (C) int   ldap_search_ext_s(void *ld, const char *base, int _scope, const char *filter,
                    char  **attrs,
                    int attrsonly,
                    LDAPControl **serverctrls,
                    LDAPControl **clientctrls,
                    timeval  *timeout,
                    int sizelimit,
                    void **res);                    // LDAPMessage
extern (C) char* ldap_first_attribute(
                    void *ld,
                    void *entry,
                    void **ber);
extern (C) char* ldap_next_attribute(
                    void *ld,
                    void *entry,
                    void *ber );
extern (C) berval** ldap_get_values_len(
                    void *ld,
                    void *entry,
                    char *attr);

extern (C) int ldap_bind_s(void *ld, const char *who, const char *cred, int method);
extern (C) int ldap_unbind(void *ld);


enum LDAP_SCOPE_BASE = 0x0000,
    LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE,
    LDAP_SCOPE_ONELEVEL = 0x0001,
    LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL,
    LDAP_SCOPE_SUBTREE = 0x0002,
    LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE,
    LDAP_SCOPE_SUBORDINATE = 0x0003, /* OpenLDAP extension */
    LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE,
    LDAP_SCOPE_DEFAULT = -1;         /* OpenLDAP extension */

enum LDAP_AUTH_SIMPLE = 0x80U;

enum LDAP_OPT_PROTOCOL_VERSION = 0x0011U;

alias SearchEntry  = Tuple!(string, "dn", string[][string], "entry");
alias SearchResult = SearchEntry[];

class LDAPException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

struct LDAP {
    void *ldap;
    this(string uri) {
        auto r = ldap_initialize(&ldap, uri.toStringz);
        if ( r != 0 ) {
            throw new LDAPException("Can't initialize LDAP: "~to!string(ldap_err2string(r)));
        }
    }
    ///
    /// Params:
    /// search_base = string, search base
    /// search_scope = int, search scope
    /// searc_filter = string, search filter
    /// search_attre = string[], list of attributes to return. All attributes returned if null
    /// Returns:
    /// SearchResult - array of tuples(dn, entry) where dn - distinguished name, entry - dictionart of attribute and values
    /// 
    SearchResult search_s(
                string search_base,
                int search_scope,
                string search_filter = "(objectClass=*)",
                string[] search_attrs = null,
                int attrsonly = 0 ) {
        return search_ext_s(search_base, search_scope, search_filter, search_attrs,
            attrsonly, null, null, null, 0);
    }

    SearchResult search_ext_s(
                string search_base,
                int search_scope,
                string search_filter="(objectClass=*)",
                string[]     search_attrs = null,
                int          attrsonly    = 0,
                LDAPControl *serverctrls  = null,
                LDAPControl *clientctrls  = null,
                timeval     *timeout      = null,
                int          sizelimit    = 0 ) {

        SearchResult result;

        void* res;
        int r = ldap_search_ext_s(ldap, search_base.toStringz, search_scope, search_filter.toStringz,
            null, // attrs
            attrsonly,
            &serverctrls, &clientctrls,
            null, sizelimit, &res
        );
        scope(exit) {
            if (res) {
                ldap_msgfree(res);
            }
        }
        if ( r != 0 ) {
            throw new LDAPException("Can't search: "~to!string(ldap_err2string(r)));
        }
        // loop over dn's
        for(auto entry = ldap_first_entry(ldap, res);
            entry != null;
            entry = ldap_next_entry(ldap, entry) ) 
        {
            char*               c_dn = ldap_get_dn(ldap, entry);
            string[][string]    attrs;
            auto                dn = to!string(c_dn);

            std.c.stdlib.free(c_dn);
            tracef("dn: %s", dn);
            void* berp;
            // loop over attrs
            for (char * attr = ldap_first_attribute(ldap, entry, &berp);
                attr != null;
                attr = ldap_next_attribute(ldap, entry, berp) )
            {
                string attr_name = to!string(attr);

                if ( !search_attrs || canFind(search_attrs, attr_name) ) {
                    berval** values = ldap_get_values_len(ldap, entry, attr);
                    for( auto bvp = values; bvp && *bvp; bvp++) {
                        berval *bv = *bvp;
                        attrs[attr_name] ~= to!string(bv.bv_val);
                        ber_bvfree(bv);
                    }
                    // XXX here should be something like ldap_values_free_len()
                    // but valgrind indicate some errors
                    ldap_memfree(values);
                }
                ldap_memfree(attr);
            }
            ber_bvarray_free(cast(berval*)berp);
            trace(attrs);

            SearchEntry e = SearchEntry(dn, attrs);
            result ~= e;
        }
        return result;
    }
    ///
    /// LDAP synchronous bind
    /// Params:
    /// who = string, DN to bind
    /// cred = string, credentials (password in case of LDAP_AUTH_SIPLE)
    /// Returns:
    /// 0 if case of success, LDAP error otherwise
    /// 
    int bind_s(string who, string cred, int method = LDAP_AUTH_SIMPLE) {
        int r = ldap_bind_s(ldap, who.toStringz, cred.toStringz, method);
        if ( r != 0 ) {
            errorf("Can't bind: %s", to!string(ldap_err2string(r)));
        }
        return r;
    }
    int unbind() {
        return ldap_unbind(ldap);
    }
    int get_option(int option, void* outvalue) {
        return ldap_get_option(ldap, option, outvalue);
    }
    int set_option(int option, void* invalue) {
        return ldap_set_option(ldap, option, invalue);
    }
};

unittest {
    globalLogLevel(LogLevel.info);
    int proto_version;
    
    auto ldap = LDAP("ldap://ldap.forumsys.com");
    ldap.get_option(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
    if ( proto_version == 2) {
        proto_version = 3;
        ldap.set_option(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
        info("Switched to protocol version 3");
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
