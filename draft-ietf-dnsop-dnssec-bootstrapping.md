%%%
Title = "Automatic DNSSEC Bootstrapping using Authenticated Signals from the Zone's Operator"
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

This document introduces an in-band method for DNS operators to
publish arbitrary information about the zones they are authoritative
for, in an authenticated fashion and on a per-zone basis.
The mechanism allows managed DNS operators to securely announce
DNSSEC key parameters for zones under their management, including for
zones that are not currently securely delegated.

Whenever DS records are absent for a zone's delegation, this signal
enables the parent's registry or registrar to cryptographically
validate the CDS/CDNSKEY records found at the child's apex.
The parent can then provision DS records for the delegation without
resorting to out-of-band validation or weaker types of cross-checks
such as "Accept after Delay" ([@!RFC8078]).

This document updates [@!RFC8078] and replaces its Section 3 with
(#bootstrapping) of this document.

[ Ed note: Text inside square brackets ([]) is additional background
information, answers to frequently asked questions, general musings,
etc.  They will be removed before publication.
This document is being collaborated on at
<https://github.com/desec-io/draft-thomassen-dnsop-dnssec-bootstrapping/>.
The authors gratefully accept pull requests. ]

{mainmatter}

# Introduction

Securing a DNS delegation for the first time requires that the
Child's DNSSEC parameters be conveyed to the Parent through some
trusted channel.
While the communication conceptually has to occur between the Parent
registry and the DNSSEC key holder, what exactly that means and how
the communication is coordinated traditionally depends on the
relationship the Child has with the Parent:

A typical situation is that the key is held by the Child DNS
Operator; the communication thus often involes this entity.
In addition, depending on the circumstances, it may also involve the
Registrar, possibly via the Registrant (for details, see [@!RFC7344],
Appendix A).

As observed in [@!RFC7344], these dependencies result often result in
a manual process that is susceptible to mistakes and/or errors.
In addition, due to the annoyance factor of the process, involved
parties may avoid the process of getting a DS record set published in
the first place.

To alleviate these problems, automated provisioning of DS records has
been specified in ([@!RFC8078]).
It is based on the Parental Agent (registry or registrar) fetching
DNSSEC key parameters in the form of CDS and CDNSKEY records
([@!RFC7344]) from the Child zone's apex, and validating them
somehow.
This validation can be done using DNSSEC itself if the objective is
to update an existing DS record set (such as during key rollover).
However, when bootstrapping a DNSSEC delegation, the Child zone has
no existing DNSSEC validation path, and other means to ensure the
CDS/CDNSKEY records' legitimacy must be found.

For lack of a comprehensive DNS-innate solution, either out-of-band
methods have been used so far to complete the chain of trust, or
cryptographic validation has been entirely dispensed with, in
exchange for weaker types of cross-checks such as "Accept after
Delay" ([@!RFC8078] Section 3.3).
An in-band validation method for enabling DNSSEC has been missing.

This document aims to close this gap by introducing an in-band method
for DNS Operators to publish arbitrary information about the zones
they are authoritative for, in an authenticated manner and on a
per-zone basis.
The mechanism allows managed DNS Operators to securely announce
DNSSEC key parameters for zones under their management.
The Parent can then use this signal to cryptographically validate the
CDS/CDNSKEY records found at an insecure Child zone's apex, and upon
success secure the delegation.

While applicable to the vast majority of domains, the protocol does
not support certain edge cases, such as excessively long Child zone
names, or DNSSEC bootstrapping for in-bailiwick domains (see
(#limitations)).

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], and [@!RFC8078].


## Terminology

This section defines the terminology used in this document.

CDS/CDNSKEY
: This notation refers to CDS and/or CDNSKEY, i.e., one or both.

Child
: The entity on record that has the delegation of the domain from the
  Parent.

Child DNS Operator
: The entity that maintains and publishes the zone information for
  the Child DNS.

Parent
: The domain in which the Child in registered.

Parental Agent
: The entity that has the authority to insert DS records into the
  Parent zone on behalf of the Child.
  (It could the the registry, registrar, a reseller, or some other
  authorized entity.)

Signaling Domain
: A hostname from the Child's NS record set, prefixed with the label
  `_signal`.
  There are as many Signaling Domains as there are distinct NS
  targets.

Signaling Name
: The labels that are prefixed to a Signaling Domain in order to
  identify a Signaling Type and a Child zone's name (see
  (#signalingnames)).

Signaling Record
: A DNS record located at a Signaling Name under a Signaling Domain.
  Signaling Records are used by the Child DNS Operator to publish
  information about the Child.

Signaling Type
: A signal type identifier, such as `_dsboot` for DNSSEC bootstrapping.

Signaling Zone
: The zone which is authoritative for a given Signaling Domain.


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


{#signaling}
# Signaling

When setting up initial trust, the Child zone's CDS/CDNSKEY RRsets
need to be authenticated.
This is achieved using an authentication signal from the Child DNS
Operator that the Parent can discover and validate, thus transferring
trust from the Child DNS Operator to the Child zone.


## Chain of Trust

If a Child DNS Operator implements the protocol, each Signaling Zone
MUST be signed and securely delegated, i.e. have a valid DNSSEC chain
of trust.

For example, when performing DNSSEC bootstrapping for a Child zone
with NS records `ns1.example.net` and `ns2.example.net`, the Child
DNS Operator needs to ensure that a valid DNSSEC chain of trust
exists for the zone(s) that are authoritative for the Signaling
Domains `_signal.ns1.example.net` and `_signal.ns2.example.net`.


{#signalingnames}
## Signaling Names

To publish a piece of information about the Child zone in an
authenticated fashion, the Child DNS Operator MUST publish one or
more Signaling Records at a Signaling Name under each Signaling Domain.

Signaling Records MUST be accompanied by RRSIG records created with
the corresponding Signaling Zone's key(s).  The type and contents
of these Signaling Records are detailed in (#signalingrecords).

The Signaling Name identifies the Child and the Signaling Type.
It is identical to the Child name (with the final root label removed),
prefixed with a label containing the Signaling Type.

# Bootstrapping a DNSSEC Delegation

Child DNS Operators and Parental Agents who wish to use CDS/CDNSKEY
records for DNSSEC bootstrapping SHOULD support the protocol
described in this section.

{#signalingrecords}
## Signaling Consent to Act as the Child's Signer

To confirm its willingness to act as the Child's delegated signer and
authenticate the Child's CDS/CDNSKEY RRsets, the Child DNS Operator
MUST co-publish them at the corresponding Signaling Name under each
Signaling Domain as defined in (#signalingnames).

Existing use of CDS/CDNSKEY records is specified at the Child apex
only ([@!RFC7344], Section 4.1).  This protocol extends the use of
these record types to non-apex owner names for the purpose of DNSSEC
bootstrapping.  To exclude the possibility of semantic collision,
there MUST NOT be a zone cut at a Signaling Name.

Unlike the CDS/CDNSKEY records at the Child's apex, Signaling
Records MUST be signed with the corresponding Signaling Zone's
key(s).  Their contents MUST be identical to the corresponding
records published at the Child's apex.

### Example

For the purposes of bootstrapping the Child zone `example.co.uk` with
NS records `ns1.example.net` and `ns2.example.net`, the required
Signaling Domains are `_signal.ns1.example.net` and
`_signal.ns2.example.net`.

In the zones containing these domains, the Child DNS Operator
authenticates the CDS/CDNSKEY records found at the Child's apex by
co-publishing them at the names:
```
_dsboot.example.co.uk._signal.ns1.example.net
_dsboot.example.co.uk._signal.ns2.example.net
```
The records are accompanied by RRSIG records created using the key(s)
of the respective Signaling Zone.

{#bootstrapping}
## Validating CDS/CDNSKEY Records for DNSSEC Bootstrapping

This section replaces Section 3 of [@!RFC8078].

To validate a Child's CDS/CDNSKEY RRset for DNSSEC bootstrapping, the
Parental Agent, knowing both the Child zone name and its NS
hostnames, MUST execute the following steps:

1. verify that the Child is not currently securely delegated;

2. query the CDS/CDNSKEY records at the Child zone apex directly from
   each of the authoritative servers listed in the delegation's NS
   record set;

3. query the CDS/CDNSKEY records located at the Signaling Name under
   each Signaling Domain using a trusted DNS resolver and enforce
   DNSSEC validation;

4. check (separately by record type) that all record sets retrieved
   in Steps 2 and 3 have equal contents;

If the above steps succeed without error, the CDS/CDNSKEY records are
successfully validated, and the Parental Agent can proceed with the
publication of the DS record set under the precautions described in
[@!RFC8078], Section 5.

If, however, an error condition occurs, in particular:

- in Step 1: the Child is already securely delegated;

- in Step 2: any failure during the retrieval of the CDS/CDNSKEY
  records located at the Child apex from any of the authoritative
  nameservers;

- in Step 3: any failure to retrieve the CDS/CDNSKEY RRsets located
  at the Signaling Name under any Signaling Domain, including failure
  of DNSSEC validation, or unauthenticated data (AD bit not set);

- in Step 4: inconsistent responses (for at least one of the types),
  including a record set that is empty in one of Steps 2 or 3, but
  non-empty in the other;

the Parental Agent MUST abort the procedure.

### Example

To verify the CDS/CDNSKEY records for the Child `example.co.uk`, the
Parental Agent (assuming that the Child delegation's NS records are
`ns1.example.net` and `ns2.example.net`)

1. checks that the Child domain is not yet securely delegated;

2. queries CDS/CDNSKEY records for `example.co.uk` directly from
   `ns1.example.net` and `ns2.example.net`;

3. queries and validates the CDS/CDNSKEY records located at (see
   (#signalingnames))

```
_dsboot.example.co.uk._signal.ns1.example.net
_dsboot.example.co.uk._signal.ns2.example.net
```

4. checks that the CDS/CDNSKEY record sets retrieved in Steps 2
   and 3 agree across responses.

If all these steps succeed, the Parental Agent can proceed to publish
a DS record set as indicated by the validated CDS/CDNSKEY records.

{#triggers}
## Triggers

[ Clarity of this section needs to be improved. ]

Parental Agents SHOULD trigger the procedure described in
(#bootstrapping) once one of the following conditions is fulfilled:

  - The Parental Agent receives a new or updated NS record set for a
    Child;

  - The Parental Agent encounters Signaling Records during a
    proactive, opportunistic scan (e.g. daily queries for the
    Signaling Records of some or all of its delegations);

  - The Parental Agent encounters Signaling Records for its Children
    during a scan (e.g. daily) of known Signaling Domains (derived
    from the NS records found in the Parent zone).
    The scan is completed by either

     * performing a targeted NSEC walk (starting with the Parent
       domain prepended to the Signaling Domain, such as
       `co.uk._signal.ns1.example.net`), or by

     * performing a zone transfer of the zone containing (the
       relevant portion of) the Signaling Domain, if the Signaling
       Zone operator allows it, and iterating over its contents.

  - Any other condition as deemed appropriate by local policy.

One of the inputs of the bootstrapping algorithm in (#bootstrapping)
is the NS record set of the Child's delegation.
It is therefore necessary to establish knowledge of the delegation's
NS record set before firing the trigger.

In some cases, the trigger context contains reliable information
about the Child's delegation, such as when bootstrapping is triggered
by the registrant changing their NS record set, or during a daily
scan of existing delegations.
In such cases, the delegation's NS RRset can be used as is.

In cases where the trigger context does not provide sufficient
knowledge of the NS record set, the Parental Agent MUST fetch the
delegation's NS record set and ensure that the proper NS record set
is fed to the bootstrapping algorithm ((#bootstrapping)).

In particular, when discovering Signaling Names by means of an NSEC
walk or zone transfer, the Parental Agent MUST NOT assume that the
nameserver(s) under whose Signaling Domain(s) a Signaling Name is
discovered is in fact authoritative for the corresponding Child.
Before firing the trigger for a particular candidate Child, the
Parental Agent MUST ascertain that the Child's delegation actually
contains the nameserver hostname under whose Signaling Domain the
scan occurred.

{#limitations}
## Limitations

As a consequence of Step 3 in (#bootstrapping), DS bootstrapping does
not work for in-bailiwick delegations, as no pre-existing chain of
trust to the Child domain is available during bootstrapping.

The protocol is further restricted by the fact that the fully
qualified Signaling Names fit within the general limits that apply to
DNS names (such as their length and label count).


# Operational Recommendations

## Child DNS Operator

To keep the size of the Signaling Zones minimal and bulk processing
efficient (such as via NSEC walks or zone transfers), Child DNS
Operators SHOULD remove Signaling Records which are found to have
been acted upon.

Signaling Domains SHOULD be delegated as zones of their own, so
that the Signaling Zone's apex coincides with the Signaling
Domain (such as `_signal.ns1.example.net`).
While it is permissible for the Signaling Domain to be contained
in a Signaling Zone of fewer labels (such as `example.net`), a
zone cut ensures that bootstrapping activities do not require
modifications of the zone containing the nameserver hostname.

In addition, Signaling Zones SHOULD use NSEC to allow efficient
discovery of pending bootstrapping operations by means of zone
walking (see (#triggers)).  This is especially useful for bulk
processing after a Child DNS Operator has enabled the protocol.

## Parental Agent

It is RECOMMENDED to perform queries within Signaling Domains
((#bootstrapping)) with an (initially) cold resolver cache as to
retrieve the most current information regardless of TTL.
(When a batch job is used to attempt bootstrapping for a large number
of delegations, the cache does not need to get cleared in between.)

[It is expected that Signaling Records have few consumers only, so
that caching would not normally have a performance benefit.
Perhaps it is thus better to RECOMMEND low TTLs instead?]


# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

## Child DNS Operator-side

* Knot DNS supports manual creation of non-apex CDS/CDNSKEY records.

* PowerDNS supports manual creation of non-apex CDS/CDNSKEY records.

* Proof-of-concept Signaling Domains with several thousand Signaling
  Names exist at `_signal.ns1.desec.io` and `_signal.ns2.desec.org`.

* Another DNS operator has implemented the protocol (synthesizing
  Signaling Records for a significant number of domains).

* The authors are planning to develop a tool for automatic generation
  of signaling records.

## Parental Agent-side

* A tool to retrieve and process Signaling Records for bootstrapping
  purposes, either directly or via zone walking, is available at
  <https://github.com/desec-io/dsbootstrap>.
  The tool outputs the validated DS records which then can be added
  to the Parent zone.

* Some registries/registrars (e.g. .cl, GoDaddy) are working on
  implementations of the protocol.


# Security Considerations

The protocol adds authentication to the CDS/CDNSKEY-based
bootstrapping concept of [@!RFC8078], while removing nothing.
Its security level is therefore strictly higher than that of existing
approaches described in that document (e.g. "Accept after Delay").
Apart from this general improvement, the same Security Considerations
apply as in [@!RFC8078].

The level of rigor in (#bootstrapping) is needed to prevent
publication of a half-baked DS RRset (authorized only under a subset
of NS hostnames).
This ensures, for example, that an operator in a multi-homed setup
cannot enable DNSSEC unless all other operators agree.
[ TODO In principle, this applies to any CDS update. Should we phrase
it as a general update to [@!RFC8078]? ]

[ Thoughts on the Chain of Trust:

Actors in the chain(s) of trust of the Signaling Zone(s) (the DNS
Operator themselves, plus entities further up in the chain) can
undermine the protocol.
However,

  * that's possible with CDS/CDNSKEY, too (new method is not weaker);
  * if the Child DNS Operator doesn't trust the zones in which its NS
    hostnames live (including their nameservers' A records) because
    their path from the root is untrusted, you probably don't want to
    trust that operator as a whole;
  * when bootstrapping is done upon receipt of a new NS record set,
    the window of opportunity is very small;
  * mitigation exists by diversifying e.g. the nameserver hostname's
    TLDs, which is advisable anyways;
  * correct bootstrapping is easily monitored by the Child DNS
    Operator.

]

# IANA Considerations

**TODO:** reserve `_dsauth`?

This document has no IANA actions.

# Acknowledgements

Thanks to Brian Dickson, Ondřej Caletka, John R. Levine, Christian
Elmerot, and Oli Schacher for reviewing draft proposals and offering
comments and suggestions.

Thanks also to Steve Crocker, Hugo Salgado, and Ulrich Wisser for
early-stage brainstorming.

{backmatter}


# Change History (to be removed before publication)

* draft-ietf-dnsop-dnssec-bootstrapping-01

> Introduced Signaling Type prefix (`_dsboot`), renamed Signaling Name
  infix from `_dsauth` to `_signal`.


* draft-ietf-dnsop-dnssec-bootstrapping-00

> Editorial changes.


* draft-thomassen-dnsop-dnssec-bootstrapping-03

> Clarified importance of record cleanup by moving paragraph up.

> Pointed out limitations.

> Replace [@!RFC8078] Section 3 with our (#bootstrapping).

> Changed `_boot` label to `_dsauth`.

> Removed hashing of Child name components in Signaling Names.

> Editorial changes.


* draft-thomassen-dnsop-dnssec-bootstrapping-02

> Reframed as an authentication mechanism for RFC 8078.

> Removed multi-signer use case (focus on RFC 8078 authentication).

> Triggers need to fetch NS records (if not implicit from context).

> Improved title.

> Recognized that hash collisions are dealt with by Child apex check.


* draft-thomassen-dnsop-dnssec-bootstrapping-01

> Add section on Triggers.

> Clarified title.

> Improved abstract.

> Require CDS/CDNSKEY records at the Child.

> Reworked Signaling Name scheme.

> Recommend using cold cache for consumption.

> Updated terminology (replace "Bootstrapping" by "Signaling").

> Added NSEC recommendation for Bootstrapping Zones.

> Added multi-signer use case.

> Editorial changes.


* draft-thomassen-dnsop-dnssec-bootstrapping-00

> Initial public draft.
