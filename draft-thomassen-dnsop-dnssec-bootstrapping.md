%%%
Title = "DNSSEC Bootstrapping"
abbrev = "dnssec-bootstrapping"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
area = "Internet"
workgroup = "DNSOP Working Group"
date = @TODAY@

[seriesInfo]
name = "Internet-Draft"
value = "@DOCNAME@"
stream = "IETF"
status = "standard"

[[author]]
initials = "P."
surname = "Thomassen"
fullname = "Peter Thomassen"
organization = "deSEC, Secure Systems Engineering"
[author.address]
 email = "peter@desec.io"
[author.address.postal]
 city = "Berlin"
 country = "Germany"
%%%


.# Abstract

This document describes an authenticated in-band method for automatic
signaling of a DNS zone's delegation signer information from the zone's DNS
operator.  The zone's registrar or registry may subsequently use this
signal for automatic DS record provisioning in the parent.

{mainmatter}


# Introduction

**TODO remove**: this section is inspired by [@!RFC7344], Section 1.

The first time a DNS Operator signs a zone, they need to communicate
the keying material to the Parent.  Depending on the desires of the
Parent, the Child might send their DNSKEY record, a DS record, or
both.

So far, out-of-band methods are typically used to complete the chain
of trust.  In-band methods exist, in particular based on the CDS and
CDNSKEY record types as specified in [@!RFC7344] and [@!RFC8078].
However, such communication is only authenticated when performing a
rollover of the Child's keys represented in the parent.  An
authenticated in-band channel for enabling DNSSEC so far has been
missing.

How the keying material is conveyed to the Parent during initial DNSSEC
bootstrapping depends on the relationship the Child has with the Parent.
In many cases this is a manual process -- and not an easy one.  The
communication has to occur between the DNS Operator and, depending on
the circumstances, the Registry or the Registrar, possibly via the
Registrant (for details, see [@!RFC7344], Appendix A).  Any manual
process is susceptible to mistakes and/or errors.  In addition, due to
the annoyance factor of the process, Operators may avoid the process
of getting a DS record set published at the Parent.

DNSSEC provides data integrity to information published in DNS; thus,
DNS publication can be used to automate maintenance of delegation
information.  This document describes a method to automate
publication of inital DS records for a hitherto insecure delegation.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], and [@!RFC8078].

This document describes a method for automating maintenance of the
delegation trust information and proposes a polled/periodic trigger
for simplicity.  Some users may prefer a different trigger, for
example, a button on a web page, a REST interface, or a DNS NOTIFY.
These alternate additional triggers are not discussed in this
document.


## Terminology

The terminology we use is defined in this section.  The highlighted
roles are as follows:

Child
: The entity on record that has the delegation of the domain
  from the Parent.

Parent
: The domain in which the Child is registered.

Child DNS Operator
: The entity that maintains and publishes the zone information
  for the Child DNS.

Parental Agent
: The entity that the Child has a relationship with to change
  its delegation information.

Signaling Name
: Given an authoritative nameserver hostname from the Child's
  NS record set, that hostname prefixed with one label
  encoding the Child's name (left-most label) and the label
  `_boot` (second-to-left-most label).

Signaling Zone
: The zone that owns a given Signaling Name.

CDS/CDNSKEY
: This notation refers to CDS and/or CDNSKEY, i.e., one or both.


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

# Description {#description}

There are number of different models for managing initial trust, but
in the general case, the child wants to enable global validation.  As
long as the child is insecure, DNS answers can be forged.  The goal
is to promote the child from insecure to secure as soon as reasonably
possible by the parent.  This means that the period from the child's
publication of CDS/CDNSKEY RRset to the parent publishing the
synchronized DS RRset should be as short as possible.

This goal is achieved by transferring trust from the Child DNS Operator.

## Preconditions

In order to use this technique, a Child DNS Operator needs to fulfill
the following conditions:

1. The Signaling Zones need to be under the Child DNS Operator's
   control.

2. The Child DNS Operator MUST ensure that each Signaling Zone is
   securely delegated, i.e. has a valid DNSSEC chain of trust from
   the root.

3. The Child DNS Operator MUST publish CDS/CDNSKEY records at the
   Child's apex, as described in [@!RFC7344].

### Example

When performing DNSSEC bootstrapping for the Child zone `example.com`
using NS records `ns1.example.net` and `ns2.example.net`, the Child
DNS Operator

1. needs to be in charge of the zone(s) containing the names
   `_boot.ns1.example.net` and `_boot.ns2.example.net`;

2. needs to ensure that a valid DNSSEC chain of trust exists for
   these names.

3. needs to publish CDS/CDNSKEY records at `example.com`.

## Bootstrapping Method

### Steps Taken by the Child DNS Operator

To perform DNSSEC bootstrapping for the Child zone, the Child DNS
Operator re-publishes the Child's CDS/CDNSKEY records under each
Signaling Name, consisting of a label identifying the Child zone's
name, the label `_boot`, and a hostname taken from the Child's NS
record set (in that order from left to right).

The identifying label is taken as the SHA-256 hash digest of the
Child zone's name in "Base 32 Encoding with Extended Hex Alphabet",
as specified in [@!RFC4648].  Trailing padding characters ("=")
are dropped.

**TODO Remove:** This is like in NSEC3, except that SHA-256 is used
instead of SHA-1 to prevent other tenants in shared hosting
environments from creating collisions.

#### Example

To bootstrap the Child zone `example.com` using NS records
`ns1.example.net` and `ns2.example.net`, the Child DNS Operator
re-publishes the Child's CDS/CDNSKEY records under the names

```
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns1.example.net
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns2.example.net
```

**TODO remove:** `echo -n example.com | openssl dgst -binary -sha256 | base32hex | tr -d =`


### Steps Taken by the Parental Agent

When the Parental Agent receives a new NS record set (or additionally
at any other time they feel it should be done), the Parental Agent,
knowing both the Child zone name and its NS hostnames,

1. queries CDS/CDNSKEY records located at each of the Signaling Names using
   standard DNS resolution;

2. performs DNSSEC validation of all responses retrieved in Step 1;

3. queries CDS/CDNSKEY records located at the Child zone apex, directly from
   each of the authoritative nameservers as given in the Child NS record set;

4. checks that all CDS/CDNSKEY record sets retrieved in Steps 1 and 3 have
   equal record contents (respectively);

5. derives a DS record set from the retrieved CDS/CDNSKEY record sets, and
   publishes it in the Parent zone as to secure the Child's delegation.

#### Example

To bootstrap the Child zone `example.com` using NS records
`ns1.example.net` and `ns2.example.net`, the Parental Agent

1. queries CDS/CDNSKEY records, using standard DNS resolution, for the names

```
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns1.example.net
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns2.example.net
```

2. performs DNSSEC validation of the responses retrieved in Step 1;

3. queries CDS/CDNSKEY records for `example.com` directly from `ns1.example.net`
   and `ns2.example.net`;

4. checks that CDS record sets retrieved in Step 1 agree across responses
   and also with the CDS record sets retrieved in Step 3; ditto for CDNSKEY;

5. publishes a DS record set according to the information retrieved in the
   previous steps.


# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

* PowerDNS supports manual creation of CDS/CDNSKEY records on non-apex names.

* TODO Proof of concept


# Security Considerations

Thoughts (to be expanded):

- We use at least on established chain of trust (via the secure delegations of
  the zones containing the NS hostnames).  As a result,
    * communication is authenticated;
    * process is immediate (no need for observing CDS/CDNSKEY records via TCP
      for several days);
    * an active on-wire attacker cannot tamper with the delegation.

- The security level of the method cannot be lower than "Accept after Delay"
  [@!RFC8078], Section 3.3, due to the consistency check of CDS/CDNSKEY records
  at the Child's apex.  In other word, we're just adding to that.

- Actors in the chain(s) of trust (upwards from the Signaling Zones) can
  undermine the protocol
    * that's also possible in the case of CDS/CDNSKEY;
    * if the Child DNS Operator doesn't control the zones in which its NS
      hostnames live (including their nameservers' A records), you probably
      don't want to trust that operator as a whole;
    * when bootstrapping is done upon receipt of a new NS record set, the
      window of opportunity is very small (and easily monitored by the Child
      DNS operator);
    * mitigation exists by diversifying e.g. the nameserver hostname's TLDs,
      which is advisable anyways.

# IANA Considerations

**TODO:** reserve `_boot`?

This document has no IANA actions.

# Acknowledgements

Thanks to TODO for reviewing draft proposals and offering comments and
suggestions.

Thanks also to Steve Crocker, Hugo Salgado, and Ulrich Wisser for early-stage
brainstorming.

{backmatter}

# Change History (to be removed before final publication)

* draft-thomassen-dnsop-dnssec-bootstrapping-00

> Initial public draft.
