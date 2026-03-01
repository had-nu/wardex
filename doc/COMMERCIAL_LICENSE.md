# Wardex Commercial Licence Agreement

**Version 1.0 — Effective Date: 2026-03-01**

> **IMPORTANT — READ CAREFULLY BEFORE USING WARDEX UNDER THIS LICENCE.**
>
> This Wardex Commercial Licence Agreement ("Agreement") is a legal agreement between
> you (either an individual or a single legal entity, referred to as "Licensee") and
> Gustavo Leão Melo, trading as had-nu ("Licensor"), the copyright holder of Wardex.
>
> By purchasing, downloading, installing, copying, or otherwise using Wardex software
> under this Agreement, Licensee agrees to be bound by its terms. If Licensee does not
> agree, Licensee may not use Wardex under this Agreement and must instead comply fully
> with the GNU Affero General Public Licence, Version 3 ("AGPL-3.0"), or cease using
> the software.
>
> If you are entering into this Agreement on behalf of a company or other legal entity,
> you represent and warrant that you have the authority to bind that entity to these terms.

---

## Part I — Definitions

**1.1 "Wardex"** means the software programme known as Wardex, including its source code,
object code, compiled binaries, associated documentation, configuration schemas, and all
modifications, updates, and successor versions made available by Licensor, as identified
in the applicable Order Form.

**1.2 "Commercial Use"** means any use of Wardex that is not fully compliant with the
AGPL-3.0, including but not limited to: (a) embedding Wardex or Derivative Works into a
Proprietary Product; (b) offering the functionality of Wardex as part of a Software-as-a-Service
("SaaS") product or managed service without disclosing the corresponding source code to all
recipients of the service under AGPL-3.0 terms; or (c) distributing Wardex as part of a
product or service under a licence that is incompatible with AGPL-3.0.

**1.3 "Derivative Works"** means any work that is based on or derived from Wardex,
including modifications, translations, adaptations, or works that incorporate all or any
part of Wardex, whether or not such works are identified as modifications of Wardex.

**1.4 "Proprietary Product"** means any software product, platform, application, or service
that is: (a) owned or controlled by Licensee or its Affiliates; and (b) distributed,
sublicensed, or made available to third parties under terms that do not permit those third
parties to receive, inspect, or modify the corresponding source code of the Proprietary Product
under a free or open-source licence.

**1.5 "Order Form"** means the purchase confirmation, invoice, or subscription agreement
executed between Licensee and Licensor that specifies the licence Tier, the number of
Authorised Developers, the Subscription Term, and the applicable Fees.

**1.6 "Authorised Developers"** means the total number of individual human persons who
(a) write, modify, or review code that directly interacts with Wardex, or (b) trigger
Wardex in any automated pipeline (CI/CD, build, release, or compliance workflow) during
the Subscription Term, as specified in the Order Form.

**1.7 "Subscription Term"** means the period during which this Agreement is active, as
specified in the Order Form, beginning on the Effective Date and automatically renewing
for successive periods of equal duration unless terminated in accordance with Part V.

**1.8 "Affiliates"** means any entity that directly or indirectly controls, is controlled by,
or is under common control with the applicable party, where "control" means ownership of
more than fifty percent (50%) of the outstanding voting securities or equivalent.

**1.9 "Internal Use"** means use of Wardex exclusively within Licensee's own internal
business operations, where the output of Wardex (reports, gate decisions, compliance data)
is consumed by Licensee's own personnel and is not made available to external third parties
as part of a commercial service offering.

---

## Part II — Licence Grant

**2.1 Commercial Licence Grant.** Subject to the terms and conditions of this Agreement,
the timely payment of all Fees, and the limitations set forth in Section 2.3, Licensor
hereby grants to Licensee a limited, non-exclusive, non-transferable, non-sublicensable
(except as expressly permitted in Section 2.2), worldwide right and licence to:

  (a) install, execute, and use Wardex on Licensee's infrastructure for Commercial Use,
      including embedding Wardex in a Proprietary Product;

  (b) make reasonable modifications to Wardex source code solely for the purpose of
      integrating Wardex with Licensee's Proprietary Product, provided such modifications
      are used exclusively within Licensee's Proprietary Product and are not distributed
      to any third party as standalone Wardex modifications;

  (c) integrate the Wardex Go packages (`pkg/`) as a library dependency within
      Licensee's Proprietary Product, without requiring Licensee to open-source
      the Proprietary Product under AGPL-3.0.

**2.2 Sublicence to End Users.** Licensee may embed Wardex in a Proprietary Product and
make that Proprietary Product available to Licensee's end users, provided that:

  (a) end users are prohibited by the terms of Licensee's end-user agreement from
      extracting, redistributing, or using Wardex independently of Licensee's Proprietary Product;

  (b) end users receive no licence rights to Wardex beyond what is necessary to use
      Licensee's Proprietary Product;

  (c) Licensee remains solely responsible for ensuring end users' compliance with
      this restriction.

**2.3 Licence Tier Limitations.** The scope of the licence granted in Section 2.1 is
limited by the Tier specified in the applicable Order Form, as described in Schedule A.
Exceeding the applicable limitations (including the Authorised Developer count) constitutes
a material breach of this Agreement and requires Licensee to promptly upgrade to a
higher Tier or reduce its usage to within the licensed limits.

**2.4 Reservation of Rights.** Licensor reserves all rights not expressly granted in this
Agreement. Nothing in this Agreement transfers ownership of any intellectual property rights
in Wardex to Licensee. The AGPL-3.0 licence remains available to any party who chooses
to comply with its terms.

---

## Part III — Restrictions

**3.1 Prohibited Actions.** Licensee shall not, and shall not permit any third party to:

  (a) **Resell or sublicence Wardex as a standalone product.** Licensee may not resell,
      sublicence, or distribute Wardex independently of Licensee's Proprietary Product.
      Wardex may only be embedded as a component; it may not be the primary marketable
      product under this Agreement.

  (b) **Compete with Licensor.** Licensee may not use Wardex to build or operate a product
      or service that is substantially similar to Wardex and is offered to third parties
      as a risk-based release gating, ISO 27001 compliance mapping, or security risk
      acceptance management tool.

  (c) **Circumvent the Authorised Developer limit.** Licensee may not use shared accounts,
      automated tokens, or other mechanisms to reduce the counted number of Authorised
      Developers below the actual number of individuals triggering Wardex.

  (d) **Remove or obscure proprietary notices.** Licensee may not remove, alter, or obscure
      any copyright notice, trademark notice, or attribution notice in Wardex source code
      or documentation.

  (e) **Claim ownership of Wardex.** Licensee may not represent to any third party that
      Licensee owns or created Wardex.

  (f) **Use outside the Subscription Term.** Licensee's right to use Wardex for Commercial
      Use ceases immediately upon expiry or termination of the Subscription Term. Continued
      Commercial Use after termination constitutes copyright infringement.

**3.2 Attribution.** Licensee shall include the following attribution in the documentation,
"About" section, or legal notices of any Proprietary Product that embeds Wardex:

  > "This product includes Wardex software (https://github.com/had-nu/wardex),
  > used under a commercial licence. Wardex is copyright © 2025–2026 Gustavo Leão Melo.
  > The Wardex name and logo are trademarks of Gustavo Leão Melo."

  Licensor may grant written permission to modify or omit this attribution for
  Enterprise Tier licensees upon request.

---

## Part IV — Fees and Payment

**4.1 Fees.** Licensee agrees to pay the Fees specified in the Order Form in advance for
each Subscription Term. All Fees are stated exclusive of applicable taxes.

**4.2 Taxes.** Licensee is responsible for all applicable taxes, levies, or duties imposed
by taxing authorities, excluding taxes on Licensor's net income. If Licensor is required to
collect any applicable taxes, those taxes will be added to Licensee's invoice.

**4.3 Payment Terms.** Fees are due and payable within thirty (30) days of the invoice date.
Overdue amounts accrue interest at 1.5% per month (or the maximum rate permitted by law,
if lower) from the due date.

**4.4 No Refunds.** All Fees are non-refundable, except as required by applicable law or
as expressly agreed in a written addendum signed by Licensor.

**4.5 Price Changes.** Licensor may change Fees for renewal Subscription Terms upon at
least sixty (60) days' written notice prior to renewal. Licensee may terminate this
Agreement in accordance with Section 5.2 if it does not agree to the revised Fees.

**4.6 Audit Right.** Licensor may, upon thirty (30) days' written notice and no more than
once per calendar year, audit Licensee's use of Wardex to verify compliance with the
Authorised Developer limits. Audits shall be conducted during normal business hours and
shall not unreasonably disrupt Licensee's operations. If an audit reveals that Licensee
has exceeded the licensed limits, Licensee shall pay the applicable underpaid Fees for
the preceding twelve (12) months plus a true-up for the current Term.

---

## Part V — Term and Termination

**5.1 Term.** This Agreement commences on the Effective Date and continues for the initial
Subscription Term specified in the Order Form, automatically renewing for successive terms
of equal duration unless either party provides written notice of non-renewal at least thirty
(30) days before the end of the then-current Subscription Term.

**5.2 Termination by Licensee.** Licensee may terminate this Agreement for any reason by
providing thirty (30) days' written notice to Licensor. No refund of pre-paid Fees shall
be issued for the remainder of the then-current Subscription Term.

**5.3 Termination by Licensor.** Licensor may terminate this Agreement:

  (a) immediately upon written notice if Licensee materially breaches any provision of
      this Agreement and fails to cure such breach within fifteen (15) days of receiving
      written notice of the breach;

  (b) immediately upon written notice if Licensee becomes insolvent, makes a general
      assignment for the benefit of creditors, or becomes subject to any bankruptcy,
      insolvency, or similar proceeding;

  (c) immediately, without notice, if Licensee violates Section 3.1(b) (competing product).

**5.4 Effect of Termination.** Upon termination or expiry of this Agreement:

  (a) all rights and licences granted to Licensee under this Agreement terminate immediately;

  (b) Licensee shall cease all Commercial Use of Wardex within fourteen (14) days;

  (c) upon Licensor's request, Licensee shall certify in writing that all copies of Wardex
      have been removed from Licensee's Proprietary Product or that Licensee has reverted
      to full AGPL-3.0 compliance;

  (d) Sections 1, 3, 4 (for amounts due), 6, 7, 8, 9, and 10 survive termination.

---

## Part VI — Intellectual Property

**6.1 Ownership.** Wardex and all copies thereof, including all Derivative Works created
by Licensor, are and shall remain the exclusive property of Licensor. This Agreement
does not transfer any ownership interest in Wardex to Licensee.

**6.2 Feedback.** If Licensee provides Licensor with any feedback, suggestions, or
recommendations regarding Wardex ("Feedback"), Licensee grants Licensor a perpetual,
irrevocable, worldwide, royalty-free licence to use, reproduce, modify, and incorporate
such Feedback into Wardex without any obligation or compensation to Licensee.

**6.3 No Implied Licences.** Except as expressly set forth herein, this Agreement grants
no licences by implication, estoppel, or otherwise.

---

## Part VII — Confidentiality

**7.1 Confidential Information.** Each party ("Receiving Party") agrees to keep confidential
all non-public information disclosed by the other party ("Disclosing Party") that is designated
as confidential or that reasonably should be understood to be confidential given the nature of
the information and the circumstances of disclosure.

**7.2 Exclusions.** Confidentiality obligations do not apply to information that: (a) is or
becomes generally known to the public without breach; (b) was known to the Receiving Party
prior to disclosure without restriction; (c) is independently developed by the Receiving Party
without use of the Disclosing Party's confidential information; or (d) is required to be
disclosed by law or court order, provided the Receiving Party gives prior written notice
where permitted.

**7.3 Duration.** Confidentiality obligations survive termination of this Agreement for
a period of three (3) years.

---

## Part VIII — Warranties and Disclaimer

**8.1 Licensor Warranties.** Licensor warrants that:

  (a) Licensor has the full right, power, and authority to enter into this Agreement
      and to grant the licences set forth herein;

  (b) to Licensor's knowledge, Wardex does not infringe any third party's copyright or
      trade secret rights as of the Effective Date.

**8.2 DISCLAIMER OF WARRANTIES.** EXCEPT AS EXPRESSLY SET FORTH IN SECTION 8.1,
WARDEX IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. LICENSOR EXPRESSLY DISCLAIMS
ALL OTHER WARRANTIES, EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
NON-INFRINGEMENT, AND ANY WARRANTIES ARISING FROM COURSE OF DEALING OR COURSE OF PERFORMANCE.

LICENSOR DOES NOT WARRANT THAT WARDEX WILL BE ERROR-FREE, THAT DEFECTS WILL BE CORRECTED,
THAT WARDEX WILL OPERATE WITHOUT INTERRUPTION, OR THAT WARDEX WILL PRODUCE ACCURATE OR
COMPLETE RISK ASSESSMENTS. WARDEX IS A DECISION-SUPPORT TOOL; SECURITY DECISIONS REMAIN
THE SOLE RESPONSIBILITY OF LICENSEE.

---

## Part IX — Limitation of Liability

**9.1 EXCLUSION OF CONSEQUENTIAL DAMAGES.** IN NO EVENT SHALL EITHER PARTY BE LIABLE
FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES, INCLUDING
BUT NOT LIMITED TO LOSS OF REVENUE, LOSS OF PROFITS, LOSS OF BUSINESS, LOSS OF DATA,
OR COST OF SUBSTITUTE GOODS OR SERVICES, ARISING OUT OF OR IN CONNECTION WITH THIS
AGREEMENT, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGES.

**9.2 LIMITATION OF LIABILITY CAP.** LICENSOR'S TOTAL CUMULATIVE LIABILITY ARISING
OUT OF OR RELATED TO THIS AGREEMENT SHALL NOT EXCEED THE FEES PAID BY LICENSEE TO
LICENSOR IN THE TWELVE (12) MONTHS IMMEDIATELY PRECEDING THE EVENT GIVING RISE TO
THE LIABILITY.

**9.3 Essential Basis.** LICENSEE ACKNOWLEDGES THAT THE LIMITATIONS OF LIABILITY
IN THIS PART IX REFLECT A REASONABLE ALLOCATION OF RISK AND ARE AN ESSENTIAL ELEMENT
OF THE BASIS OF THE BARGAIN BETWEEN THE PARTIES. LICENSOR WOULD NOT ENTER INTO THIS
AGREEMENT WITHOUT THESE LIMITATIONS.

---

## Part X — General Provisions

**10.1 Entire Agreement.** This Agreement, together with the applicable Order Form and
Schedule A, constitutes the entire agreement between the parties with respect to its
subject matter and supersedes all prior or contemporaneous agreements, understandings,
or representations, whether written or oral, regarding such subject matter.

**10.2 Order of Precedence.** In the event of a conflict between this Agreement and
an Order Form, the Order Form shall control solely with respect to the specific commercial
terms (Tier, pricing, Authorised Developer count, Subscription Term) of that Order Form.
This Agreement shall control for all other matters.

**10.3 Amendments.** This Agreement may be amended only by a written instrument signed
by authorised representatives of both parties. Licensor may update this Agreement for
future Subscription Terms upon sixty (60) days' notice; continued use after the notice
period constitutes acceptance of the amended terms.

**10.4 Assignment.** Licensee may not assign this Agreement or any rights or obligations
hereunder without Licensor's prior written consent, which shall not be unreasonably withheld.
Licensor may assign this Agreement without consent in connection with a merger, acquisition,
or sale of all or substantially all of Licensor's assets. Any purported assignment in violation
of this section is void.

**10.5 Governing Law and Dispute Resolution.**

(a) **Governing Law.** This Agreement shall be governed by and construed in 
accordance with the substantive laws of Portugal (excluding its rules on 
conflict of laws), as supplemented by mandatory provisions of European Union 
law applicable to the subject matter hereof, including but not limited to 
data protection regulations and applicable EU directives, which shall prevail 
to the extent of any inconsistency.

(b) **Negotiation.** In the event of any dispute, controversy, or claim arising 
out of or relating to this Agreement, or the breach, termination, or validity 
thereof ("Dispute"), the parties shall first attempt to resolve the Dispute 
by good-faith negotiation. Either party may initiate this process by delivering 
written notice to the other party. If the Dispute is not resolved within 
thirty (30) days of such notice (or such longer period as the parties may 
agree in writing), either party may proceed to mediation under subsection (c).

(c) **Mediation.** If negotiation fails, the parties shall submit the Dispute 
to mediation under the rules of the Centro de Arbitragem Comercial da Câmara 
de Comércio e Indústria Portuguesa (CAC), seated in Lisbon, Portugal. 
If the Dispute is not resolved within thirty (30) days of the commencement 
of mediation, either party may initiate arbitration under subsection (d).

(d) **Arbitration.** Any Dispute not resolved by negotiation or mediation shall 
be finally settled by binding arbitration under the Rules of the CAC 
(or, for Enterprise Tier disputes exceeding €100,000, optionally the 
ICC Rules), conducted by one (1) arbitrator for disputes up to €50,000, 
or three (3) arbitrators for disputes above that amount, appointed in 
accordance with the applicable rules. The seat of arbitration shall be 
Lisbon, Portugal. The language of proceedings shall be English (or 
Portuguese, if both parties agree). The arbitral award shall be final, 
binding, and enforceable in any jurisdiction pursuant to the New York 
Convention on the Recognition and Enforcement of Foreign Arbitral Awards 
(1958), to which Portugal is a signatory.

(e) **Interim Relief.** Notwithstanding the foregoing, either party may seek 
urgent interim or provisional relief, including injunctions to protect 
intellectual property rights, from any court of competent jurisdiction 
without waiving its right to arbitration.

(f) **Mandatory Consumer and B2B Protections.** Nothing in this Section 10.5 
shall be construed to limit any mandatory rights available to Licensee 
under the law of Licensee's domicile that cannot be contractually waived, 
including rights arising under the applicable national implementation of 
EU Directive 93/13/EEC or equivalent B2B protection statutes.

**10.6 Notices.** All notices required or permitted under this Agreement shall be in writing
and shall be deemed delivered: (a) when sent by email with confirmation of receipt to the
addresses specified in the Order Form; or (b) when sent by recorded post to the addresses
specified in the Order Form.

**10.7 Waiver.** Failure by either party to enforce any provision of this Agreement shall
not be deemed a waiver of future enforcement of that provision or any other provision.

**10.8 Severability.** If any provision of this Agreement is held to be unenforceable or
invalid, that provision shall be modified to the minimum extent necessary to make it
enforceable, and the remaining provisions of this Agreement shall continue in full force.

**10.9 Independent Contractors.** The parties are independent contractors. Nothing in this
Agreement creates a partnership, joint venture, agency, franchise, or employment relationship
between the parties.

**10.10 Force Majeure.** Neither party shall be in default of this Agreement to the extent
that performance is delayed or prevented by circumstances beyond that party's reasonable
control, including but not limited to acts of God, government regulations, embargoes,
or failure of third-party telecommunications infrastructure.

**10.11 Headings.** Section headings are for convenience only and shall not affect the
interpretation of this Agreement.

---

## Schedule A — Licence Tiers

The following tiers are available under this Agreement. The applicable tier is specified
in the Order Form.

### Tier 1 — Startup

| Parameter | Value |
|---|---|
| **Annual Fee** | €2,990 / year (or €299/month, billed monthly) |
| **Authorised Developers** | Up to 10 |
| **Production Services** | Up to 5 services or pipelines |
| **Commercial Use Rights** | SaaS embedding, proprietary product distribution |
| **Support** | Email support — 48-hour response SLA (business days) |
| **Updates** | Minor and patch releases during Subscription Term |
| **Eligibility** | Companies with annual recurring revenue below €1,000,000 |

### Tier 2 — Scale

| Parameter | Value |
|---|---|
| **Annual Fee** | €9,900 / year (or €990/month, billed monthly) |
| **Authorised Developers** | Up to 50 |
| **Production Services** | Up to 50 services or pipelines |
| **Commercial Use Rights** | All Startup rights |
| **Support** | Priority email support — 24-hour response SLA (business days) |
| **Updates** | All releases during Subscription Term + private roadmap access |
| **Eligibility** | No revenue restriction |

### Tier 3 — Enterprise

| Parameter | Value |
|---|---|
| **Annual Fee** | Custom — contact commercial@wardex.dev |
| **Authorised Developers** | Unlimited |
| **Production Services** | Unlimited |
| **Commercial Use Rights** | All Scale rights + white-label option (negotiated separately) |
| **Support** | Dedicated Slack/Teams channel + named support contact |
| **SLA** | Custom — 4-hour critical response available |
| **Extras** | NDA available · Security audit report · On-site/remote onboarding · Custom integration assistance |
| **Eligibility** | No restriction. Mandatory for regulated industries (financial services, healthcare, critical infrastructure) |

### Internal Enterprise Use — No Commercial Licence Required

Companies that run Wardex exclusively within their own internal CI/CD pipelines, where Wardex
output is consumed solely by their own personnel and is not made available to external users
as part of a commercial service, are operating under AGPL-3.0 Internal Use and do not require
this Commercial Licence.

If you are uncertain whether your use case requires a commercial licence, contact
**commercial@wardex.dev** for a free written use-case assessment.

---

## Contact and Commercial Enquiries

**Licensor:** Gustavo Leão Melo (had-nu)
**Email:** commercial@wardex.dev
**Repository:** https://github.com/had-nu/wardex
**Registered Address:** Remote Organisation (Portugal)

To purchase a commercial licence, initiate a use-case enquiry, or request an Order Form:

```
commercial@wardex.dev
Subject: Wardex Commercial Licence — [Tier] — [Company Name]
```

---

*Wardex Commercial Licence Agreement — Version 1.0*
*Copyright © 2025–2026 Gustavo Leão Melo. All rights reserved.*
*The Wardex name and logo are trademarks of Gustavo Leão Melo.*

*This document is provided for informational purposes. The binding commercial licence
is the fully executed Order Form and Agreement between the parties.*
