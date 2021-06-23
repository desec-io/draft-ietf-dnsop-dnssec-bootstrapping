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
signaling of a zone's delegation signer information from the zone's DNS
operator.  The zone's registrar or registry may subsequently use this
signal for automatic DS record provisioning in the parent.

{mainmatter}


# Introduction

TODO

# Terminology

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

Term
: Definition

# Description {#description}

TODO

# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

* PowerDNS supports manual creation of CDS/CDNSKEY records on non-apex names.

* TODO Proof of concept


# Security Considerations

TODO

# IANA Considerations

This document has no IANA actions.

#

# Acknowledgements

Thanks to TODO for reviewing draft proposals and offering comments and
suggestions.

Thanks also to Steve Crocker, Hugo Salgado, and Ulrich Wisser for early-stage
brainstorming.

{backmatter}

# Change History (to be removed before final publication)

* draft-thomassen-dnsop-dnssec-bootstrapping-00

> Initial public draft.

