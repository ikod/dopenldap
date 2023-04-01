/// A thin wrapper around the C OpenLDAP library libldap and utility functions.
module openldap;

import std.format : format;
import std.string : toStringz;
import core.sys.posix.sys.time : timeval;
import std.conv : to;
import std.typecons : Tuple;
import core.stdc.stdlib : free;
import std.algorithm : canFind;
import std.logger : errorf, globalLogLevel, info, infof, trace, tracef, LogLevel;

/// A structure for returning a sequence of octet strings + length.
struct berval {
    int             bv_len;
    char*           bv_val;
}
alias BerValue = berval;

/// An opaque structure used to maintain state information
/// used in encoding and decoding.
alias BerElement = void;

/// LDAP Control structure
struct ldapcontrol {
    char*           ldctl_oid;              /// numericoid of control
    berval          ldctl_value;            /// encoded value of control
    char            ldctl_iscritical;       /// criticality
}
alias LDAPControl = ldapcontrol;

/// An opaque type for a structure representing an ldap session which can encompass connections to
/// multiple servers (in the face of referrals).
alias LDAP = void;

/// An opaque type for a structure representing both ldap messages and ldap responses.
/// These are really the same, except in the case of search responses,
/// where a response has multiple messages.
alias LDAPMessage = void;

/// Frees an array of BerValues (and the array), pointed to by bvarray, returned from this API. If
/// bvarray is NULL, the routine does nothing.
///
/// See_Also: man(3) ber_bvarray_free
extern (C) void ber_bvarray_free(BerValue* bvarray);

/// Frees a BerValue, pointed to by bv, returned from this API.  If bv is NULL, the routine does
/// nothing.
///
/// See_Also: man(3) ber_bvfree
extern (C) void ber_bvfree(BerValue* bv);

/// The ldap_msgfree() routine is used to free the memory allocated for result(s) by ldap_result()
/// or ldap_search_ext_s(3) and friends.	It takes a pointer to the result or result chain to be
/// freed and returns the type of the last message in the chain.	If the parameter is NULL, the
/// function does nothing and returns zero.
/// See_Also: man(3) ldap_msgfree
extern (C) void ldap_msgfree(LDAPMessage*);

/// Used to deallocate memory used by the LDAP library, similar to free(3).
///
/// See_Also: man(3) ldap_memfree
extern (C) void ldap_memfree(void*);

/// Frees attribute values from an LDAP entry as returned by ldap_first_entry or ldap_next_entry.
///
/// See_Also: man(3) ldap_value_free_len
extern (C) void ldap_value_free_len(BerValue**);

/// ditto
extern (C) void ldap_value_free(BerValue**);

/// Gets options stored either in a LDAP handle or as global options, where applicable.
///
/// See_Also: man(3) ldap_get_option
extern (C) int ldap_get_option(LDAP* ld, int option, void* outvalue);

/// Sets options stored either in a LDAP handle or as global options, where applicable.
///
/// See_Also: man(3) ldap_set_option
extern (C) int ldap_set_option(LDAP* ld, int option, const void* invalue);

/// Allocates an LDAP structure but does not open an initial connection.
///
/// See_Also: man(3) ldap_initialize
extern (C) int   ldap_initialize(LDAP**, const char*);

/// Provides short descriptions of the various codes returned by routines in this library.
///
/// See_Also: man(3) ldap_err2string
extern (C) char* ldap_err2string(int);

/// Retrieves the first entry in a chain of search results.  It takes the result as returned by a
/// call to ldap_result(3) or ldap_search_s(3) or ldap_search_st(3) and returns a pointer to the
/// first entry in the result.
///
/// See_Also: man(3) ldap_first_entry
extern (C) void* ldap_first_entry(LDAP* ld, LDAPMessage* chain );

/// Takes the result of ldap_first_entry() and returns the next entry. Returns NULL when there are
/// no more entries.
///
/// See_Also: man(3) ldap_next_entry
extern (C) LDAPMessage* ldap_next_entry(LDAP* ld, LDAPMessage* entry);

/// Takes an entry as returned by ldap_first_entry(3) or ldap_next_entry(3) and returns a copy of
/// the entry's DN.
///
/// See_Also: man(3) ldap_get_dn
extern (C) char* ldap_get_dn(LDAP* ld, LDAPMessage* entry);

/// Perform LDAP search operations synchronously.
///
/// Params:
///   base = the DN of the entry at which to start the search
///   _scope = one of LDAP_SCOPE_BASE to search the object itself, LDAP_SCOPE_ONELEVEL to
///     search the objects's immediate children, LDAP_SCOPE_SUBTREE to search the object
///     and all its descendants, or LDAP_SCOPE_CHILDREN to search all of the descendants.
///   filter = A string representation of the filter to apply to the search. The string should
///     conform to the format specified in RFC 4515 as extended by RFC 4526. For instance,
///     "(cn=Jane Doe)". NULL may be specified to indicate the library should send the
///     filter "(objectClass=*)".
///   attrs = A null-terminated array of attribute descriptions to return from matching entries.
///   attrsonly = Set to a non-zero value if only attribute descriptions are wanted. Set to
///     zero (0) if both attribute descriptions and attribute values are wanted.
///
/// See_Also: man(3) ldap_search_ext_s
extern (C) int   ldap_search_ext_s(LDAP* ld, const char* base, int _scope, const char* filter,
                    char** attrs,
                    int attrsonly,
                    LDAPControl** serverctrls,
                    LDAPControl** clientctrls,
                    timeval*  timeout,
                    int sizelimit,
                    LDAPMessage** res);                    // LDAPMessage

/// Steps through the attributes of an LDAP entry.
/// Takes an entry as returned by ldap_first_entry(3) or ldap_next_entry(3) and returns
/// a pointer to character string containing the first attribute description in the entry.
///
/// See_Also: man(3) ldap_first_attribute
extern (C) char* ldap_first_attribute(
                    LDAP* ld,
                    LDAPMessage* entry,
                    BerElement** ber);

/// Takes the pointer returned by ldap_first_attribute in berptr to effectively step through
/// an entry's attributes. The caller is responsible for freeing the BerElement referred
/// to by berptr.
extern (C) char* ldap_next_attribute(
                    LDAP* ld,
                    LDAPMessage* entry,
                    BerElement* ber );

/// Takes an element and the name of an attribute whose values are desired and returns a
/// NULL-terminated array of pointers to BerVal structures, each containing the length and a
/// pointer to a value.
///
/// See_Also: man(3) ldap_get_values_len
extern (C) BerValue** ldap_get_values_len(
                    LDAP* ld,
                    LDAPMessage* entry,
                    char* attr);

/// Authenticates a connection at runtime and returns an LDAP error indication.
/// Params:
///   who = The DN to bind to.
///   cred = The credentials of the DN, such as a password.
///   method = The authorization method, e.g. LDAP_AUTH_SIMPLE.
extern (C) int ldap_bind_s(LDAP* ld, const char* who, const char* cred, int method);

/// Authenticates a connection at runtime and returns an LDAP error indication.
extern (C) int ldap_unbind(void *ld);

/// LDAP Search Scopes
enum LDAP_SCOPE_BASE = 0x0000,
     LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE,
     LDAP_SCOPE_ONELEVEL = 0x0001,
     LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL,
     LDAP_SCOPE_SUBTREE = 0x0002,
     LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE,
     LDAP_SCOPE_SUBORDINATE = 0x0003, /* OpenLDAP extension */
     LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE,
     LDAP_SCOPE_DEFAULT = -1;         /* OpenLDAP extension */

/// LDAP Authentication Methods
enum LDAP_AUTH_NONE = 0x00U,
     LDAP_AUTH_SIMPLE = 0x80U;

enum LDAP_OPT_PROTOCOL_VERSION = 0x0011U;

/// A single entry in an LDAP Directory Information Tree (DIT) consisting of a unique Distinguished
/// Name (dn) and a number of named attributes associated with the entry. Each named attribute of
/// the entry has an array of values.
alias SearchEntry  = Tuple!(string, "dn", string[][string], "entry");

/// An array of SearchEntry values.
alias SearchResult = SearchEntry[];

/// A base-class for LDAP-related exceptions.
class LDAPException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

/// A convenience object that is more convenient to use than directly using the C functions.
struct LDAPConnection {
    LDAP* ldap;
    this(string uri) {
        auto r = ldap_initialize(&ldap, uri.toStringz);
        if ( r != 0 ) {
            throw new LDAPException("Can't initialize LDAP: "~to!string(ldap_err2string(r)));
        }
    }

    /// Synchronously executes an LDAP search query starting from a given base DN.
    /// Params:
    ///   search_base = the DN of the entry from which the search begins
    ///   search_scope = one of LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB, etc.
    ///   search_filter = a filter determining which entries match, defaults to "(objectClass=*)"
    ///   search_attrs = a list of attributes to return or null if all attributes are desired
    ///   attrsonly = if non-zero, only attribute names are returned, if zero, values are included
    /// Returns:
    ///   SearchResult - array of tuples(dn, entry) where dn - distinguished name,
    ///       entry - dictionary of attributes and values
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

    /// ditto
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
        if (r != 0) {
            throw new LDAPException("Can't search: " ~ to!string(ldap_err2string(r)));
        }
        // loop over dn's
        for (auto entry = ldap_first_entry(ldap, res);
            entry != null;
            entry = ldap_next_entry(ldap, entry))
        {
            char*               c_dn = ldap_get_dn(ldap, entry);
            string[][string]    attrs;
            auto                dn = to!string(c_dn);

            free(c_dn);
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

    /// LDAP synchronous bind
    /// Params:
    ///   who = DN to bind
    ///   cred = credentials (password in case of LDAP_AUTH_SIMPLE)
    ///   method = The authorization method, e.g. LDAP_AUTH_SIMPLE.
    /// Returns:
    ///   0 if case of success, LDAP error otherwise
    ///
    int bind_s(string who, string cred, int method = LDAP_AUTH_SIMPLE) {
        int r = ldap_bind_s(ldap, who.toStringz, cred.toStringz, method);
        if ( r != 0 ) {
            errorf("Can't bind: %s", to!string(ldap_err2string(r)));
        }
        return r;
    }

    /// Terminates an LDAP connection.
    int unbind() {
        return ldap_unbind(ldap);
    }

    /// Returns the current value of an LDAP option.
    ///
    /// See_Also: man(3) ldap_get_option
    int get_option(int option, void* outvalue) {
        return ldap_get_option(ldap, option, outvalue);
    }

    /// Sets an LDAP option to an arbitrary value.
    ///
    /// See_Also: man(3) ldap_get_option
    int set_option(int option, void* invalue) {
        return ldap_set_option(ldap, option, invalue);
    }
}

unittest {
    globalLogLevel(LogLevel.info);
    int proto_version;

    auto ldap = LDAPConnection("ldap://ldap.forumsys.com");
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
