%%%
Title = "Automatic DNSSEC Bootstrapping using Authenticated Signals from the Zone's Operator"
abbrev = "dnssec-bootstrapping"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [7344, 8078]
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
such as "Accept after Delay".

This document deprecates the DS enrollment methods described in Section
3 of RFC 8078 in favor of (#dnssec-bootstrapping) of this document, and
also updates RFC 7344.

[ Ed note: This document is being collaborated on at
<https://github.com/desec-io/draft-ietf-dnsop-dnssec-bootstrapping/>.
The authors gratefully accept pull requests. ]

{mainmatter}

# Introduction

Securing a DNS delegation for the first time requires that the
child's DNSSEC parameters be conveyed to the parent through some
trusted channel.
While the communication conceptually has to occur between the parent
registry and the DNSSEC key holder, what exactly that means and how
the communication is coordinated traditionally depends on the
relationship the child has with the parent.

A typical situation is that the key is held by the child DNS
operator; the communication thus often involves this entity.
In addition, depending on the circumstances, it may also involve the
Registrar, possibly via the Registrant (for details, see [@!RFC7344],
Appendix A).

As observed in [@!RFC7344], these dependencies often result in a manual
process that is susceptible to mistakes and/or errors.
In addition, due to the annoyance factor of the process, involved
parties may avoid the process of getting a DS record set (RRset)
published in the first place.

To alleviate these problems, automated provisioning of DS records has
been specified in ([@!RFC8078]).
It is based on the parental agent (registry or registrar) fetching
DNSSEC key parameters from the CDS and CDNSKEY records ([@!RFC7344])
located at the child zone's apex, and validating them somehow.
This validation can be done using the child's existing DNSSEC chain of
trust if the objective is to update an existing DS RRset (such as
during key rollover).
However, when bootstrapping a DNSSEC delegation, the child zone has
no existing DNSSEC validation path, and other means to ensure the
CDS/CDNSKEY records' legitimacy must be found.

Due to the lack of a comprehensive DNS-innate solution, either
out-of-band methods have been used so far to complete the chain of
trust, or cryptographic validation has been entirely dispensed with, in
exchange for weaker types of cross-checks such as "Accept after
Delay" ([@!RFC8078] Section 3.3).
[@!RFC8078] does not define an in-band validation method for enabling
DNSSEC.

This document aims to close this gap by introducing an in-band method
for DNS operators to publish arbitrary information about the zones
they are authoritative for, in an authenticated manner and on a
per-zone basis.
The mechanism allows managed DNS operators to securely announce
DNSSEC key parameters for zones under their management.
The parent can then use this signal to cryptographically validate the
CDS/CDNSKEY RRsets found at an insecure child zone's apex and, upon
success, secure the delegation.

While applicable to the vast majority of domains, the protocol does
not support certain edge cases, such as excessively long child zone
names, or DNSSEC bootstrapping for domains with in-domain nameservers
only (see (#limitations)).

DNSSEC bootstrapping is just one application of the generic signaling
mechanism specified in this document.
Other applications might arise in the future, such as publishing
operational metadata or auxiliary information which the DNS operator
likes to make known (e.g., API endpoints for third-party interaction).

Readers are expected to be familiar with DNSSEC [@BCP237].


## Terminology

This section defines the terminology used in this document.

CDS/CDNSKEY
: This notation refers to CDS and/or CDNSKEY, i.e., one or both.

Child
: see [@!RFC9499] Section 7

Child DNS operator
: The entity that maintains and publishes the zone information for
  the child DNS.

Parent
: see [@!RFC9499] Section 7

Parental agent
: The entity that has the authority to insert DS records into the
  parent zone on behalf of the child.
  (It could be the registry, registrar, a reseller, or some other
  authorized entity.)

Signaling domain
: A hostname from the child's NS RRset, prefixed with the label
  `_signal`.
  There are as many signaling domains as there are distinct NS
  targets.

Signaling name
: The labels that are prefixed to a signaling domain in order to
  identify a signaling type and a child zone's name (see
  (#signalingnames)).

Signaling record
: A DNS record located at a signaling name under a signaling domain.
  Signaling records are used by the child DNS operator to publish
  information about the child.

Signaling type
: A signal type identifier, such as `_dsboot` for DNSSEC bootstrapping.

Signaling zone
: The zone which is authoritative for a given signaling record.


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


# Updates to RFCs

The DS enrollment methods described in Section 3 of [@!RFC8078] are
deprecated and SHOULD NOT be used.
Child DNS operators and parental agents who wish to use CDS/CDNSKEY
records for initial DS enrollment SHOULD instead support the
authentication protocol described in (#dnssec-bootstrapping) of this
document.

In order to facilitate publication of signaling records for the purpose
of DNSSEC bootstrapping (see (#signalingrecords)), the first bullet
("Location") of [@!RFC7344] Section 4.1 is removed.


{#signaling}
# Signaling

This section describes the general mechanism by which a child DNS
operator can publish an authenticated signal about a child zone.
Parental agents (or any other party) can then discover and process the
signal.
Authenticity is ensured through standard DNSSEC validation.


## Chain of Trust

If a child DNS operator implements this specification, each signaling
zone MUST be signed and be validatable by the parental agent (i.e., have
a valid publicly resolvable DNSSEC chain of trust).
This is typically achieved by securely delegating each signaling zone.

For example, when publishing a signal that relates to a child zone
with NS records `ns1.example.net` and `ns2.example.org`, the child
DNS operator needs to ensure that the parental agent has a valid DNSSEC
chain of trust for the zone(s) that are authoritative for the signaling
domains `_signal.ns1.example.net` and `_signal.ns2.example.org`.


{#signalingnames}
## Signaling Names

To publish information about the child zone in an
authenticated fashion, the child DNS operator MUST publish one or
more signaling records at a signaling name under each signaling domain.

Signaling records MUST be accompanied by RRSIG records created with
the corresponding signaling zone's key(s).
The type and contents of these signaling records depend on the type of
signal.

The signaling name identifies the child and the signaling type.
It is identical to the child name (with the final root label removed),
prefixed with a label containing the signaling type.

{#dnssec-bootstrapping}
# Bootstrapping a DNSSEC Delegation

When the child zone's CDS/CDNSKEY RRsets are used for setting up initial
trust, they need to be authenticated.
This is achieved by co-publishing the child's CDS/CDNSKEY RRsets as an
authenticated signal as described in (#signaling).
The parent can discover and validate it, thus transferring trust from
the child DNS operator nameservers' chain of trust to the child zone.

This protocol is not intended for updating an existing DS RRset.
For this purpose, the parental agent can validate the child's
CDS/CDNSKEY RRsets directly, using the chain of trust established by
the existing DS RRset ([@!RFC7344] Section 4).


{#signalingrecords}
## Signaling Consent to Act as the Child's Signer

To confirm its willingness to act as the child's delegated signer and
authenticate the child's CDS/CDNSKEY RRsets, the child DNS operator
MUST co-publish them at the corresponding signaling name under each
signaling domain, excluding those that would fall within the child
domain ((#signalingnames)).
For simplicity, the child DNS operator MAY also co-publish the child's
CDS/CDNSKEY RRsets under signaling domains within the child domain,
although those signaling domains are not used for validation
((#cds-auth)).

Unlike the CDS/CDNSKEY RRsets at the child's apex, a signaling
record set MUST be signed with the corresponding signaling zone's
key(s).  Its contents MUST be identical to the corresponding
RRset published at the child's apex.

Existing use of CDS/CDNSKEY records was specified at the child apex
only ([@!RFC7344], Section 4.1).  This protocol extends the use of
these record types to non-apex owner names for the purpose of DNSSEC
bootstrapping.  To exclude the possibility of semantic collision,
there MUST NOT be a zone cut at a signaling name.

### Example

For the purposes of bootstrapping the child zone `example.co.uk` with NS
records `ns1.example.net`, `ns2.example.org`, and `ns3.example.co.uk`,
the required signaling domains are `_signal.ns1.example.net` and
`_signal.ns2.example.org`.

In the zones containing these domains, the child DNS operator
authenticates the CDS/CDNSKEY RRsets found at the child's apex by
co-publishing them at the names:
```
_dsboot.example.co.uk._signal.ns1.example.net
_dsboot.example.co.uk._signal.ns2.example.org
```
These RRsets are signed with DNSSEC just like any other zone data.

Publication of signaling records under the in-domain name
`_signal.ns3.example.co.uk` is not required.

{#cds-auth}
## Validating CDS/CDNSKEY Records for DNSSEC Bootstrapping

To validate a child's CDS/CDNSKEY RRset for DNSSEC bootstrapping, the
parental agent, knowing both the child zone name and its NS
hostnames, MUST execute the following steps:

1. verify that the child has no DS records published at the parent and
   that at least one of its nameservers is outside the child domain;

2. query the CDS/CDNSKEY RRset at the child zone apex directly from
   each of the authoritative servers as determined by the delegation's
   (parent-side) NS RRset, without caching;

3. query the CDS/CDNSKEY RRset located at the signaling name under
   each signaling domain (except those falling within the child domain)
   using a trusted DNS resolver and enforce DNSSEC validation;

4. check (separately by record type) that all RRsets retrieved
   in Steps 2 and 3 have equal contents;

If the above steps succeed without error, the CDS/CDNSKEY RRsets are
successfully verified, and the parental agent can proceed with the
publication of the DS RRset under the precautions described in
[@!RFC8078], Section 5.

The parental agent MUST abort the procedure if an error
condition occurs, in particular:

- in Step 1: the child is already securely delegated or has in-domain
  nameservers only;

- in Step 2: any failure during the retrieval of the CDS/CDNSKEY
  RRset located at the child apex from any of the authoritative
  nameservers;

- in Step 3: any failure to retrieve the CDS/CDNSKEY RRsets located
  at the signaling name under any signaling domain, including failure
  of DNSSEC validation, or unauthenticated data (AD bit not set);

- in Step 4: inconsistent responses (for at least one of the types),
  including an RRset that is empty in one of Steps 2 or 3, but
  non-empty in the other.

### Example

To verify the CDS/CDNSKEY RRsets for the child `example.co.uk`, the
parental agent (assuming that the child delegation's NS records are
`ns1.example.net`, `ns2.example.org`, and `ns3.example.co.uk`)

1. checks that the child domain is not yet securely delegated;

2. queries the CDS/CDNSKEY RRsets for `example.co.uk` directly from
   `ns1.example.net`, `ns2.example.org`, and `ns3.example.co.uk`
   (without caching);

3. queries and validates the CDS/CDNSKEY RRsets located at (see
   (#signalingnames); `ns3.example.co.uk` is ignored because it is
   in-domain)

```
_dsboot.example.co.uk._signal.ns1.example.net
_dsboot.example.co.uk._signal.ns2.example.org
```

4. checks that the CDS/CDNSKEY RRsets retrieved in Steps 2
   and 3 agree across responses.

If all these steps succeed, the parental agent can proceed to publish
a DS RRset as indicated by the validated CDS/CDNSKEY RRset.

As in-domain signaling names do not have a chain of trust at
bootstrapping time, the parental agent does not consider them during
validation.
Consequently, if all NS hostnames are in-domain, validation cannot be
completed, and DS records are not published.

{#triggers}
## Triggers

Parental agents SHOULD trigger the procedure described in (#cds-auth)
once one of the following conditions is fulfilled:

  - The parental agent receives a new or updated NS RRset for a
    child;

  - The parental agent receives a notification indicating that the child
    wishes to have its CDS/CDNSKEY RRset processed;

  - The parental agent encounters a signaling record during a proactive,
    opportunistic scan (e.g., daily queries of signaling records for
    some or all of its delegations);

  - The parental agent encounters a signaling record during an NSEC walk
    or when parsing a signaling zone (e.g., when made available via AXFR
    by the child DNS operator);

  - Any other condition as deemed appropriate by local policy.

Timer-based trigger mechanisms (such as scans) exhibit undesirable
properties with respect to processing delay and scaling; on-demand
triggers (like notifications) are preferable. Whenever possible, child
DNS operators and parental agents are thus encouraged to use them,
reducing both delays and the amount of scanning traffic.

Most types of discovery (such as daily scans of delegations) are based
directly on the delegation's NS RRset.
In this case, these NS names can be used as is by the bootstrapping
algorithm ((#cds-auth)) for querying signaling records.

Some discovery methods, however, do not imply reliable knowledge of the
delegation's NS RRset.
For example, when discovering signaling names by performing an NSEC
walk or zone transfer of a signaling zone, the parental agent MUST NOT
assume that the nameserver(s) under whose signaling domain(s) a
signaling name appears is actually authoritative for the corresponding
child.

Instead, whenever a list of "bootstrappable domains" is obtained other
than directly from the parent, the parental
agent MUST ascertain that the child's delegation actually contains the
nameserver hostname seen during discovery, and ensure that signaling
record queries are only made against the proper set of nameservers as
listed in the child's delegation from the parent.


{#limitations}
## Limitations

As a consequence of Step 3 in (#cds-auth), DS bootstrapping does not
work for fully in-domain delegations, as no pre-existing chain of
trust to the child domain is available during bootstrapping.
(As a workaround, one can add an out-of-domain nameserver to the
initial NS RRset and remove it once bootstrapping is completed.
Automation for this is available via CSYNC records, see [@!RFC7477].)

Fully qualified signaling names must by valid DNS names.
Label count and length requirements for DNS names ([@!RFC1035] Section
3.1) imply that the protocol does not work for unusually long child
domain names or NS hostnames.


# Operational Recommendations

## Child DNS Operator

CDS/CDNSKEY records and corresponding signaling records MUST NOT be
published without the zone owner's consent.
Likewise, the child DNS operator MUST enable the zone owner to signal
the desire to turn off DNSSEC by publication of the special-value
CDS/CDNSKEY RRset specified in [@!RFC8078] Section 4.
To facilitate transitions between DNS operators, child DNS operators
SHOULD support the multi-signer protocols described in [@RFC8901].

Signaling domains SHOULD be delegated as standalone zones, so
that the signaling zone's apex coincides with the signaling domain (such
as `_signal.ns1.example.net`).
While it is permissible for the signaling domain to be contained
in a signaling zone of fewer labels (such as `example.net`), a
zone cut ensures that bootstrapping activities do not require
modifications of the zone containing the nameserver hostname.

Once a Child DNS Operator determines that specific signaling record sets
have been processed (e.g., by seeing the result in the parent zone),
they are advised to remove them.
This will reduce the size of the signaling zone, and facilitate more
efficient bulk processing (such as via zone transfers).

## Parental Agent

In order to ensure timely DNSSEC bootstrapping of insecure domains,
stalemate situations due to mismatch of stale cached records (Step 4 of
(#cds-auth)) need to be avoided.
It is thus RECOMMENDED to perform queries into signaling domains with an
(initially) cold resolver cache, or using some other method for
retrieving fresh data from authoritative servers.


# Security Considerations

The DNSSEC bootstrapping method introduced in this document is based on
the (now deprecated) approaches described in [@!RFC8078] Section 3, but
adds authentication to the CDS/CDNSKEY concept.
Its security level is therefore strictly higher than that of existing
approaches described in that document (e.g., "Accept after Delay").
Apart from this general improvement, the same Security Considerations
apply as in [@!RFC8078].

The level of rigor in (#cds-auth) is needed to prevent publication of a
ill-conceived DS RRset (authorized only under a subset of NS hostnames).
This ensures, for example, that an operator in a multi-homed setup
cannot enable DNSSEC unless all other operators agree.

In any case, as the child DNS operator has authoritative knowledge of
the child's CDS/CDNSKEY records, it can readily detect fraudulent
provisioning of DS records.

In order to prevent the parents of nameserver hostnames from becoming a
single point of failure for a delegation (both in terms of resolution
availability and for the trust model of this protocol), it is advisable
to diversify the path from the root to the child's nameserver hostnames,
such as by using different and independently operated TLDs for each one.


# IANA Considerations

Per [@!RFC8552], IANA is requested to add the following entries to the
"Underscored and Globally Scoped DNS Node Names" registry:

    +---------+------------+------------+
    | RR Type | _NODE NAME | Reference  |
    +---------+------------+------------+
    | CDS     | _signal    | [This RFC] |
    | CDNSKEY | _signal    | [This RFC] |
    +---------+------------+------------+

**Note to the RFC Editor**: please replace "This RFC" in the above table with a proper reference.


# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

In addition to the information in this section, deployment is tracked
by the community at <https://github.com/oskar456/cds-updates>.

## Child DNS Operator-side

* Operator support:

  - Cloudflare has implemented bootstrapping record synthesis for all
    signed customer zones.
  - Glauca HexDNS publishes bootstrapping records for its customer
    zones.
  - deSEC performs bootstrapping record synthesis for its zones using
    names `_signal.ns1.desec.io` and `_signal.ns2.desec.org`.

* Authoritative nameserver support:
  - Knot DNS supports signaling record synthesis since version 3.3.5.
  - An implementation of bootstrapping record synthesis in PowerDNS is
    available at https://github.com/desec-io/desec-ns/pull/46.

## Parental Agent-side

* ccTLD:
  - SWITCH (.ch, .li) has implemented authentication of consumed CDS
    records based on this draft.
  - .cl is working on an implementation.

* gTLD:
  - Knipp has implemented consumption of DNSSEC bootstrapping records
    in its TANGO and CORE registry systems.
  - A deployment of this is running at .swiss.

* Registrars:
  - Glauca has implemented authenticated CDS processing.
  - GoDaddy is working on an implementation.

* A tool to retrieve and process signaling records for bootstrapping
  purposes, either directly or via zone walking, is available at
  <https://github.com/desec-io/dsbootstrap>.
  The tool outputs the validated DS records which then can be added
  to the parent zone.


# Acknowledgements

Thanks to Brian Dickson, Ondřej Caletka, John R. Levine, Christian
Elmerot, Oli Schacher, Donald Eastlake, Libor Peltan, Warren Kumari,
Scott Rose, Linda Dunbar, Tim Wicinski, Paul Wouters, Paul Hoffman,
Peter Yee, Benson Muite, Roman Danyliw for reviewing draft proposals and
offering comments and suggestions.

Thanks also to Steve Crocker, Hugo Salgado, and Ulrich Wisser for
early-stage brainstorming.

{backmatter}


# Change History (to be removed before publication)

* draft-ietf-dnsop-dnssec-bootstrapping-10


* draft-ietf-dnsop-dnssec-bootstrapping-09

> Addressed comments by Paul Wouters

> Editorial nits by Roman Danyliw

> Editorial nits by Benson Muite

> Editorial nits by Peter Yee

> Editorial nit by Scott Rose

> Editorial suggestion from John Levine

* draft-ietf-dnsop-dnssec-bootstrapping-08

> Editorial changes from AD Review

> Updated implementation section

> Change capitalization of terms from terminology section


* draft-ietf-dnsop-dnssec-bootstrapping-07

> Add Glauca registrar implementation

> Editorial changes to Security Considerations

> Add/discuss on-demand triggers (notifications)


* draft-ietf-dnsop-dnssec-bootstrapping-06

> Add section "Updates to RFCs"

> Editorial nits

> Editorial changes from Secdir early review


* draft-ietf-dnsop-dnssec-bootstrapping-05

> Editorial changes


* draft-ietf-dnsop-dnssec-bootstrapping-04

> Added consent considerations.

> Editorial changes.


* draft-ietf-dnsop-dnssec-bootstrapping-03

> Updated Implementation section.

> Typo fix.


* draft-ietf-dnsop-dnssec-bootstrapping-02

> Clarified that RFC 8078 Section 3 is not replaced, but its methods are
  deprecated.

> Added new deployments to Implementation section.

> Included NSEC walk / AXFR as possible triggers for DS bootstrapping.

> Editorial changes.


* draft-ietf-dnsop-dnssec-bootstrapping-01

> Allow bootstrapping when some (not all) NS hostnames are in bailiwick.

> Clarified Operational Recommendations according to operator feedback.

> Turn loose Security Considerations points into coherent text.

> Do no longer suggest NSEC-walking Signaling Domains.
  (It does not work well due to the Signaling Type prefix. What's more,
  it's unclear who would do this: Parents know there delegations and can
  do a targeted scan; others are not interested.)

> Editorial changes.

> Added IANA request.

> Introduced Signaling Type prefix (`_dsboot`), renamed Signaling Name
  infix from `_dsauth` to `_signal`.


* draft-ietf-dnsop-dnssec-bootstrapping-00

> Editorial changes.


* draft-thomassen-dnsop-dnssec-bootstrapping-03

> Clarified importance of record cleanup by moving paragraph up.

> Pointed out limitations.

> Replace [@!RFC8078] Section 3 with our (#cds-auth).

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
