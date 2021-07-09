%%%
Title = "Authenticated Bootstrapping of DNSSEC Delegations"
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

[[author]]
initials = "N."
surname = "Wisiol"
fullname = "Nils Wisiol"
organization = "deSEC, Technische Universität Berlin"
[author.address]
 email = "nils@desec.io"
[author.address.postal]
 city = "Berlin"
 country = "Germany"
%%%


.# Abstract

This document describes an authenticated in-band method for automatic
signaling of a Child DNS zone's delegation signer information from the zone's DNS
operator(s).  The zone's registrar or registry may subsequently use this
signal for automatic DS record provisioning in the parent zone.

{mainmatter}


# Introduction

**TODO remove**: this section is inspired by [@!RFC7344], Section 1.

The first time a Child DNS Operator signs a zone, they need to communicate
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
The communication has to occur between the Child DNS Operator and, depending
on the circumstances, the Registry or the Registrar, possibly via the
Registrant (for details, see [@!RFC7344], Appendix A).  In many cases,
this is a manual process -- and not an easy one.  Any manual
process is susceptible to mistakes and/or errors.  In addition, due to
the annoyance factor of the process, involved parties may avoid the
process of getting a DS record set published at the Parent.

DNSSEC provides data integrity to information published in DNS; thus,
DNS publication can be used to automate maintenance of delegation
information.  This document describes a method to automate
publication of initial DS records for a hitherto insecure delegation.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], and [@!RFC8078].

This document describes a method for automated provisioning of the
delegation trust information and proposes a simple provisioning trigger
mechanism.  Some users may prefer a different trigger.
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

Bootstrapping Domain(s)
: For any given authoritative nameserver hostname from the Child's
  NS record set, the hostname prefixed with the label `_boot` is one
  of the Bootstrapping Domains for the Child Zone.

Bootstrapping Zone
: The zone which is authoritative for a given Bootstrapping Domain.

Signaling Name
: A Bootstrapping Domain prefixed with a label derived from the
  Child zone's name.

CDS/CDNSKEY
: This notation refers to CDS and/or CDNSKEY, i.e., one or both.

Base32hex Encoding
: "Base 32 Encoding with Extended Hex Alphabet" as per [@!RFC4648].


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

# Description {#description}

When setting up initial trust, the child generally wants to enable
global validation.
As long as the child is insecure, DNS answers can be forged.  The goal
is to promote the child from insecure to secure as soon as reasonably
possible by the parent.  This means that the period from the child's
publication of CDS/CDNSKEY RRset to the parent publishing the
synchronized DS RRset should be as short as possible.

This goal is achieved by transferring trust from the Child DNS Operator.
Implementation by Child DNS Operators and Parental Agents is RECOMMENDED.

## Preconditions

If a Child DNS Operator implements the protocol, the following conditions
have to be met:

1. The Child DNS Operator SHOULD publish CDS/CDNSKEY records at the
   Child's apex, as described in [@!RFC7344].

2. Each Bootstrapping Zone MUST be part securely delegated zone, i.e.
   have a valid DNSSEC chain of trust from the root.

### Example

When performing DNSSEC bootstrapping for the Child zone `example.com`
using NS records `ns1.example.net` and `ns2.example.net`, the Child
DNS Operator

1. should publish CDS/CDNSKEY records at `example.com`;

2. needs to ensure that a valid DNSSEC chain of trust exists for the
   zone(s) that are authoritative for the Bootstrapping Domains
   `_boot.ns1.example.net` and `_boot.ns2.example.net`.


{#signaling}
## Signaling Intent to Act as the Child's Signer

To signal that a Child DNS Operator whishes to act as the Child's
delegated signer, the Child DNS Operator MUST publish one or more
signaling records at the Child's Signaling Name under each
Bootstrapping Domain.  The signaling records are

- a PTR record containing the Child's name as the target;

- one or more other DNS records, depending on the specific use
  case as described below.

As these records belong to the corresponding Bootstrapping Zone,
they MUST be signed with that zone's keys (as opposed to signing
them with the Child zone's keys).

The Signaling Name contains a label derived from the Child's name.
This label MUST be equal to the SHA-256 hash digest of the Child's
name in "Base 32 Encoding with Extended Hex Alphabet", as specified
in [@!RFC4648].  Trailing padding characters ("=") MUST be dropped.

**TODO Remove Note 1:** The purpose of the hash function is to avoid
the possibility of exceeding the maximum length of a DNS name.  This
could occur if the Child name was used as is.

**TODO Remove Note 2:** The encoding choice is like in NSEC3, except
that SHA-256 is used instead of SHA-1.  This is to prevent other
tenants in shared hosting environments from creating collisions.

**TODO Remove Note 3:** To support DNS operators with many zones,
the Signaling Name should support sharding of Child names, i.e.,
be separated into a couple of labels.

## Bootstrapping of DNSSEC Delegations

{#signalingrecords}
### Signaling Records

To announce its willingness to act as the Child's delegated signer,
the Child DNS operator publishes a copy of the Child's CDS/CDNSKEY
records at the corresponding Signaling Name under each
Bootstrapping Domain as defined in #signaling.

Previous use of CDS/CDNSKEY records is specified at the apex only
([@!RFC7344], Section 4.1).  This protocol extends the use of these
record types at non-apex owner names for the purpose of DNSSEC
bootstrapping.  To exclude the possibility of semantic collision,
there MUST NOT be a zone cut at a Signaling Name.

#### Example

For the purposes of bootstrapping the Child zone `example.com` with
NS records `ns1.example.net` and `ns2.example.net`, the required
Bootstrapping Domains are `_boot.ns1.example.net` and
`_boot.ns2.example.net`.  In the zones containing these domains, the
Child DNS Operator

- publishes a PTR record pointing to `example.com.`, and
- publishes the Child's CDS/CDNSKEY records

at the names

```
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns1.example.net
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns2.example.net
```

where `kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g` is
derived from the DNS Child Zone's name `example.com`.  The records are
accompanied by RRSIG records created using the key(s) of the
respective Bootstrapping Zone.

**TODO:** 1.) Should hash input include trailing dot?
2.) Should hash input include bootstrapping domain (to prevent DNAME redirects)?
(Command was: `echo -n example.com | openssl dgst -binary -sha256 | base32hex | tr -d =`)
3.) Should the hash use wire format?

{#bootstrapping}
### Steps Taken by the Parental Agent

When a Parental Agent implementing this protocol receives a new or updated NS
record set for a Child, the Parental Agent, knowing both the Child
zone name and its NS hostnames,

1. MUST verify that the Child is not currently securely delegated;

2. MUST query the CDS/CDNSKEY records located at the Child zone apex,
   directly from each of the authoritative nameservers as given in the
   Child NS record set;

3. MUST query the PTR record located at each of the Signaling Names
   and verify that its content is equal to the Child's name;

4. MUST query the CDS/CDNSKEY records located at each of the Signaling
   Names;

5. MUST check (separately by record type) that all record sets
   retrieved in Steps 2, 3 and 4 have equal contents;

6. SHOULD derive a DS record set from the retrieved CDS/CDNSKEY record
   sets and publish it in the Parent zone, as to secure the Child's
   delegation.

For above queries, the Parental Agent MUST use a trusted and validating
DNS resolver and MUST treat responses with unauthenticated data
(AD bit not set) as an error condition, unless indicated otherwise.

If an error condition occurs before Step 6, in particular:

- The Child is already securely delegated (Step 1),

- Any failure during the retrieval of the CDS/CDNSKEY records located
  at the Child apex from the Child's authoritative nameservers (Step 2),

- The PTR record does not match (Step 3),

- DNS resolution failure during retrieval of CDS/CDNSKEY records from
  any Signaling Name, or failure of DNSSEC validation (Step 4),

- Inconsistent responses (Step 5),

the Parental Agent MUST abort the procedure and MUST NOT proceed to Step 5.

In addition to triggering this procedure whenever the Child's NS
records are updated, the Parental Agent MAY also trigger the
procedure at any other time deemed appropriate by local policy.

#### Example

To bootstrap the Child zone `example.com` using NS records
`ns1.example.net` and `ns2.example.net`, the Parental Agent

1. checks that the Child zone is not yet securely delegated;

2. queries CDS/CDNSKEY records for `example.com` directly from
   `ns1.example.net` and `ns2.example.net`;

3. queries the PTR record located at the Signaling Names
```
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns1.example.net
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns2.example.net
```
   and verifies that the record content is `example.com.`;

4. queries CDS/CDNSKEY records located at the same Signaling Names;

5. checks that the PTR record sets retrieved in Step 3 agree across
   responses; ditto for the CDS/CDNSKEY record sets retrieved in
   Step 2 and Step 4;

6. publishes a DS record set according to the information retrieved in the
   previous steps.

#### Opt-out

As a special case of Step 2 failure, the Child MAY opt out from DNSSEC
bootstrapping by publishing a CDS/CDNSKEY record with algorithm 0 and
other fields as specified in [@!RFC8078], Section 4, at its apex.
(This opt-out mechanism is without regard to whether the Child DNS
Operator signs the zones and publishes records at the Signaling Names.)


## Possible Extensions

By provisioning other types of signaling records, the Child DNS Operator
can convey signals that pertain to use cases other than bootstrapping
a DNSSEC delegation.

### Multi-Signer Setups: Onboarding a Signing Party

[@!RFC8901] describes multi-signer models in which several Child DNS
Operators serve the same Child zone.  In one of these scenarios
(Model 2, [@!RFC8901], Section 2.1.2), each Child DNS Operator holds
a unique KSK set and ZSK set to sign the zone.

To ensure smooth resolution of Child zone queries, this scheme
demands that participating Child DNS Operators import the ZSK sets
of the other providers into their DNSKEY RRset.  When a new Child
DNS Operator is joining the scheme, this synchronization has to
occur before the new operator's nameserver hostnames are included
in the Child's NS record set.  So far, it has been assumed that the
ZSK export/import would happen through some proprietary API at each
DNS operator.

However, the mechanism described in (#signaling) provides a public,
authenticated, in-band, read-only interface to the Child DNS Operator.
It can therefore be used by a Child DNS Operator to make its own
set of DNSKEY records available for querying by other signing parties,
so that they can retrieve, validate, and import them.

#### Signaling Records

Given a Child zone `example.com` that is already securely delegated
with authoritative nameservers `ns1.example.net` and `ns2.example.net`,
we consider how a new Child DNS Operator using nameservers
`ns3.example.org` and `ns4.example.org` can distribute its ZSK set to
the existing signing parties, in order to join the multi-signer group.

The Bootstrapping Domains corresponding to the new Child DNS Operator's
nameservers are `_boot.ns3.example.org` and `_boot.ns4.example.org`.
In the zones containing these domains, the new Child DNS Operator

- publishes a PTR record pointing to `example.com.`, and
- publishes a DNSKEY record set containing the ZSK set that the
  operator will use for signing the Child zone,

at the names

```
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns3.example.org
kdsqdtnelusqanhnhg8o0d72ekf6gbtbjsmj1aojq895b1me353g._boot.ns4.example.org
```

where the first label is calculated as described above.  The records
are accompanied by RRSIG records created using the key(s) of the
respective Bootstrapping Zone.

Note that DNSKEY records are not restricted to apex owner names
([@!RFC4035], Section 2.1).  However, only apex DNSKEY records are
used for DNSSEC validation ([@!RFC4035], Section 5).  As Signaling
Names do not occur on zone cuts (see (#signalingrecords)), the use
of DNSKEY records described here does not interfere with existing
DNSKEY uses.

#### Import

Once the owner of `example.com` informs the existing signing parties
of the joining Child DNS Operator's nameserver hostnames, the
existing parties can use an algorithm similar to the one given in
(#bootstrapping) to query and validate the joining operator's ZSK
set, and then include it in their DNSKEY sets.

To finish the joining process, CDS/CDNSKEY records may be used to
propagate the joint delegation signer information to the parent
([@!RFC8901], Section 8).  Signing parties can then synchronize the
Child's NS record set to include the joining operator's
authoritative hostnames, and use CSYNC to amend the NS record set
at the Parent.


## Operational Recommendations

Bootstrapping Domains SHOULD be delegated as zones of their own, so
that the Bootstrapping Zone's apex coincides with the Bootstrapping
Domain (such as `_boot.ns1.example.net`).
While it is permissible for the Bootstrapping Domain to be contained
in a Bootstrapping Zone of fewer labels (such as `example.net`), a
zone cut ensures that bootstrapping activities do not require
modifications of the zone containing the nameserver hostname.

In addition, Bootstrapping Zones SHOULD use NSEC to allow consumers
to efficiently discover pending bootstrapping operations by means of
zone walking.


# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

* Knot DNS supports manual creation of CDS/CDNSKEY records on non-apex names.

* PowerDNS supports manual creation of CDS/CDNSKEY records on non-apex names.

* Proof-of-concept bootstrapping domains exist at `_boot.ns1.desec.io`
  and `_boot.ns2.desec.org`.  Signaling Names can be discovered via
  NSEC walking.  Child zones can be discovered by querying PTR for a
  Signaling Name.


# Security Considerations

Thoughts (to be expanded):

- We use at least one established chain of trust (via the secure delegations of
  the zones containing the NS hostnames).  As a result,
    * communication is authenticated;
    * process is immediate (no need for observing CDS/CDNSKEY records via TCP
      for several days);
    * an active on-wire attacker cannot tamper with the delegation.

- When validating against CDS/CDNSKEY records at the Child's apex, the security
  level of the method is strictly higher than the "accept CDS/CDNSKEY after a
  while"-approch that is already in use at several ccTLD registries ("Accept
  after Delay", [@!RFC8078], Section 3.3).  This is because the method described
  here adds stronger guarantees, but removes nothing.  Perhaps this means that
  co-publication of CDS/CDNSKEY at the Child apex should be mandatory.  (This in
  turn may interact somehow with the Child's opt-out option.)

- Actors in the chain(s) of trust of the zone(s) used for bootstrapping (the DNS
  Operator themselves, plus entities further up in the chain) can undermine the
  protocol.  However,
    * that's also possible in the case of CDS/CDNSKEY (see previous point);
    * if the Child DNS Operator doesn't control the zones in which its NS
      hostnames live (including their nameservers' A records) because the path
      from the root is untrusted, you probably don't want to trust that operator
      as a whole;
    * when bootstrapping is done upon receipt of a new NS record set, the
      window of opportunity is very small (and easily monitored by the Child
      DNS operator);
    * mitigation exists by diversifying e.g. the nameserver hostname's TLDs,
      which is advisable anyways.

# IANA Considerations

**TODO:** reserve `_boot`?

This document has no IANA actions.

# Acknowledgements

Thanks to Nils Wisiol for helping in the conceptual development of the
protocol, and to Brian Dickson for reviewing draft proposals and offering
comments and suggestions.

Thanks also to Steve Crocker, Hugo Salgado, and Ulrich Wisser for early-stage
brainstorming.

{backmatter}

# Change History (to be removed before final publication)

* draft-thomassen-dnsop-dnssec-bootstrapping-00

> Initial public draft.
