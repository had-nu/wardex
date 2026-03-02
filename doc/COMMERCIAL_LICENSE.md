# Wardex Commercial Licence Agreement

**Version 1.1 — Effective Date: 1 March 2026**

> **IMPORTANT — READ CAREFULLY BEFORE USING WARDEX UNDER THIS LICENCE.**
>
> This Wardex Commercial Licence Agreement ("Agreement") is a legal agreement between
> you (either an individual or a single legal entity, referred to as "Licensee") and
> André Gustavo Leão de Melo Ataíde, acting under the project name had-nu ("Licensor"),
> the sole copyright holder of Wardex.
>
> By executing an Order Form that references this Agreement, or by downloading, installing,
> or otherwise using Wardex for Commercial Use, Licensee confirms that it has read,
> understood, and agrees to be bound by this Agreement. If Licensee does not agree, it
> must not use Wardex for Commercial Use and must instead comply fully with the GNU Affero
> General Public Licence, Version 3 ("AGPL-3.0"), or cease using the software.
>
> If you are entering into this Agreement on behalf of a legal entity, you represent and
> warrant that you have authority to bind that entity to these terms. This Agreement is
> binding upon execution of an Order Form by both parties.

---

## Part I — Definitions

**1.1 "Wardex"** means the software programme known as Wardex (repository:
`github.com/had-nu/wardex`), including its source code, object code, compiled binaries,
associated documentation, configuration schemas, and all modifications, updates, patch
releases, and successor versions made available by Licensor during the Subscription Term,
as identified in the applicable Order Form.

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
parties to receive, inspect, or modify the corresponding source code of the Proprietary
Product under a free or open-source licence.

**1.5 "Order Form"** means the written purchase confirmation, invoice, or subscription
agreement executed between Licensee and Licensor that specifies the licence Tier, the
number of Authorised Developers, the Subscription Term, the applicable Fees, and the
contact details of both parties. The Order Form is incorporated by reference into this
Agreement and constitutes part of the binding contract between the parties.

**1.6 "Authorised Developers"** means the total number of individual human persons who,
during the Subscription Term: (a) write, modify, or review code that directly interacts
with Wardex; or (b) trigger Wardex in any automated pipeline (CI/CD, build, release, or
compliance workflow), as specified in the Order Form.

**1.7 "Subscription Term"** means the period during which this Agreement is active, as
specified in the Order Form, beginning on the Effective Date of the Order Form and
renewing only in accordance with Section 5.1.

**1.8 "Affiliates"** means any entity that directly or indirectly controls, is controlled
by, or is under common control with the applicable party, where "control" means ownership
of more than fifty percent (50%) of the outstanding voting securities or equivalent.

**1.9 "Internal Use"** means use of Wardex exclusively within Licensee's own internal
business operations, where the output of Wardex (reports, gate decisions, compliance data)
is consumed solely by Licensee's own personnel and is not made available to external
third parties as part of a commercial service offering. Internal Use is free under
AGPL-3.0 and does not require this Commercial Licence.

**1.10 "Personal Data"** has the meaning assigned to it in Regulation (EU) 2016/679
(the General Data Protection Regulation, "GDPR").

---

## Part II — Licence Grant

**2.1 Commercial Licence Grant.** Subject to the terms and conditions of this Agreement,
the timely payment of all Fees, and the Tier limitations set forth in Section 2.3,
Licensor hereby grants to Licensee a limited, non-exclusive, non-transferable,
non-sublicensable (except as expressly permitted in Section 2.2), worldwide right and
licence to:

  (a) install, execute, and use Wardex on Licensee's infrastructure for Commercial Use,
      including embedding Wardex in a Proprietary Product;

  (b) make reasonable modifications to Wardex source code solely for the purpose of
      integrating Wardex with Licensee's Proprietary Product, provided such modifications
      are used exclusively within Licensee's Proprietary Product and are not distributed
      to any third party as standalone Wardex modifications;

  (c) integrate the Wardex Go packages (`pkg/`) as a library dependency within
      Licensee's Proprietary Product, without requiring Licensee to open-source the
      Proprietary Product under AGPL-3.0.

**2.2 Sublicence to End Users.** Licensee may embed Wardex in a Proprietary Product and
make that Proprietary Product available to Licensee's end users, provided that:

  (a) end users are prohibited by the terms of Licensee's end-user agreement from
      extracting, redistributing, or using Wardex independently of Licensee's Proprietary Product;

  (b) end users receive no licence rights to Wardex beyond what is necessary to use
      Licensee's Proprietary Product; and

  (c) Licensee remains solely responsible for ensuring end users' compliance with these
      restrictions and for any breach thereof.

**2.3 Tier Limitations.** The scope of the licence granted in Section 2.1 is limited by
the Tier specified in the applicable Order Form, as described in Schedule A. Exceeding the
applicable Tier limitations (including the Authorised Developer count) constitutes a
material breach of this Agreement and requires Licensee to promptly notify Licensor,
upgrade to the appropriate Tier, and pay any applicable true-up Fees.

**2.4 Reservation of Rights.** Licensor reserves all rights not expressly granted herein.
Nothing in this Agreement transfers ownership of any intellectual property right in
Wardex to Licensee. The AGPL-3.0 licence remains available to any party who chooses
to comply fully with its terms.

---

## Part III — Restrictions

**3.1 Prohibited Actions.** Licensee shall not, and shall not permit any third party to:

  (a) **Resell Wardex as a standalone product.** Licensee may not resell, sublicence, or
      distribute Wardex independently of Licensee's Proprietary Product. Wardex may only
      be embedded as a component; it may not be the primary marketable product offered
      under this Agreement.

  (b) **Compete with Licensor.** During the Subscription Term and for a period of twelve
      (12) months after its expiry or termination, Licensee may not use Wardex, or
      knowledge derived from accessing Wardex source code under this Agreement, to build
      or operate a product or service that is substantially similar in primary function to
      Wardex — namely, a risk-based CI/CD release gate combined with ISO 27001 or
      equivalent compliance mapping and cryptographic risk acceptance management — and
      that is offered commercially to third parties. This restriction: (i) applies
      only within the European Economic Area and any other jurisdiction where Licensor
      then has active commercial operations; (ii) does not restrict Licensee from
      embedding Wardex in a broader product that also performs other functions; and
      (iii) does not restrict Licensee's independent development activities unrelated
      to Wardex. This clause shall be interpreted in accordance with Article 101 TFEU
      and applicable national competition law, and shall be limited or disapplied to
      the minimum extent necessary to comply with any applicable mandatory law.

  (c) **Circumvent Authorised Developer limits.** Licensee may not use shared accounts,
      generic service tokens, or other mechanisms to undercount the actual number of
      individuals triggering Wardex.

  (d) **Remove proprietary notices.** Licensee may not remove, alter, or obscure any
      copyright notice, trademark notice, or attribution notice in Wardex source code,
      documentation, or compiled output.

  (e) **Misrepresent ownership.** Licensee may not represent to any third party that
      Licensee owns, created, or holds intellectual property rights in Wardex itself.

  (f) **Use after termination.** Licensee's right to use Wardex for Commercial Use ceases
      immediately upon expiry or termination of the Subscription Term. Continued Commercial
      Use after that date constitutes copyright infringement and entitles Licensor to seek
      all available legal remedies.

**3.2 Attribution.** Licensee shall include the following notice in the documentation,
"About" screen, or legal notices file of any Proprietary Product that embeds Wardex:

  > *"This product includes Wardex software (https://github.com/had-nu/wardex),
  > incorporated under a commercial licence. Wardex is copyright © 2025–2026
  > André Gustavo Leão de Melo Ataíde. The Wardex name is an unregistered trademark
  > (™) of André Gustavo Leão de Melo Ataíde."*

  Licensor may grant written permission to modify or omit this attribution for Enterprise
  Tier licensees upon request.

---

## Part IV — Fees and Payment

**4.1 Fees.** Licensee agrees to pay the Fees specified in the Order Form, in advance,
for each Subscription Term. All Fees are stated exclusive of applicable taxes.

**4.2 Taxes.** Licensee is responsible for all applicable taxes, levies, or duties imposed
by taxing authorities on Licensee's acquisition of the licence, excluding taxes on
Licensor's net income. Where Licensor is required to collect VAT or equivalent indirect
tax, such amount will be itemised on the invoice separately.

**4.3 Payment Terms and Late Payment Interest.** Fees are due and payable within thirty
(30) calendar days of the invoice date. Overdue amounts shall accrue default interest
from the due date at the applicable statutory rate for late payment in commercial
transactions. For transactions governed by Portuguese law, this rate is determined in
accordance with Decreto-Lei n.º 62/2013, de 10 de maio (implementing EU Directive
2011/7/EU), being the reference rate applied by the European Central Bank to its main
refinancing operations plus eight (8) percentage points, as published biannually in the
Diário da República. If the applicable mandatory rate in Licensee's jurisdiction is higher,
that rate applies. Recovery of reasonable collection costs is also permitted under
applicable law. Contractual interest shall not exceed the maximum rate permitted by
Article 1146.º of the Código Civil or equivalent applicable law.

**4.4 No Refunds.** Fees paid are non-refundable, except: (a) as required by mandatory
applicable law; (b) where Licensor materially breaches the warranty in Section 8.1(c)
and fails to provide the remedy described therein; or (c) as agreed in a written addendum
signed by both parties.

**4.5 Price Changes on Renewal.** Licensor may change Fees applicable to a renewal
Subscription Term upon at least sixty (60) days' prior written notice. Licensee may
elect to terminate this Agreement in accordance with Section 5.2 rather than accept the
revised Fees. Commencement of a renewal Term by Licensee constitutes acceptance of the
revised Fees for that Term.

**4.6 Usage Audit.** Licensor may, upon thirty (30) days' prior written notice and no
more than once per calendar year, verify Licensee's compliance with the Authorised
Developer count. Audits shall be conducted remotely unless remote verification is
insufficient, and shall not unreasonably disrupt Licensee's operations. If an audit
reveals underpayment, Licensee shall pay the shortfall for the preceding twelve (12)
months within thirty (30) days of the audit findings. If the shortfall exceeds fifteen
percent (15%) of Fees due, Licensee shall also reimburse Licensor's reasonable audit costs.

---

## Part V — Term and Termination

**5.1 Term and Renewal.** This Agreement commences on the Effective Date of the applicable
Order Form and continues for the initial Subscription Term. At the end of each Term, this
Agreement renews automatically for a successive term of equal duration unless either party
provides written notice of non-renewal at least thirty (30) days before the end of the
then-current Term. Licensor will send a renewal reminder at least forty-five (45) days
before each renewal date.

**5.2 Termination by Licensee.** Licensee may terminate this Agreement at any time by
providing thirty (30) days' prior written notice to Licensor. Pre-paid Fees for the
unexpired portion of the then-current Subscription Term are non-refundable except as
provided in Section 4.4.

**5.3 Termination by Licensor.** Licensor may terminate this Agreement:

  (a) for material breach, upon fifteen (15) days' written notice specifying the breach,
      if Licensee fails to cure within that period;

  (b) immediately upon written notice if Licensee becomes insolvent, makes a general
      assignment for the benefit of creditors, or is subject to bankruptcy or equivalent
      insolvency proceedings not dismissed within sixty (60) days; or

  (c) immediately upon written notice if Licensee wilfully and materially violates
      Section 3.1(a) (resale) or Section 3.1(f) (use after termination).

**5.4 Effect of Termination.** Upon termination or expiry:

  (a) all rights and licences granted to Licensee terminate immediately (or, for 5.3(a),
      at the end of the cure period);

  (b) Licensee shall cease all Commercial Use within fourteen (14) days and, within that
      period, either remove Wardex from its Proprietary Product or bring it into full
      AGPL-3.0 compliance;

  (c) upon Licensor's written request, Licensee shall provide written confirmation of
      compliance with (b) within seven (7) days; and

  (d) Sections 1, 3, 4 (amounts due), 6, 7, 8.2, 9, 10, 11, and 12.5–12.12, and this
      Section 5.4 survive termination indefinitely.

---

## Part VI — Intellectual Property

**6.1 Ownership.** Wardex and all copies thereof, including all Derivative Works created
by Licensor, remain the exclusive intellectual property of Licensor. This Agreement does
not transfer ownership of any intellectual property right to Licensee. Licensor retains
all moral rights (direitos morais) in Wardex to the extent provided by applicable law.

**6.2 Feedback.** If Licensee provides Licensor with feedback, suggestions, or
recommendations regarding Wardex ("Feedback"), Licensee grants Licensor a perpetual,
irrevocable, worldwide, royalty-free licence to use, reproduce, modify, and incorporate
such Feedback into Wardex or other products, without obligation or compensation.

**6.3 No Implied Licences.** Except as expressly set forth herein, this Agreement grants
no licences by implication, estoppel, or otherwise.

**6.4 Trademark.** "Wardex" is an unregistered trademark (™) of André Gustavo Leão de
Melo Ataíde. Licensee acquires no trademark rights under this Agreement beyond the
attribution right in Section 3.2.

---

## Part VII — Confidentiality

**7.1 Confidential Information.** Each party ("Receiving Party") shall keep confidential
all non-public, proprietary information of the other party ("Disclosing Party") that is
designated as confidential or that a reasonable person would understand to be confidential
given the nature of the information and circumstances of disclosure.

**7.2 Exclusions.** Confidentiality obligations do not apply to information that:
(a) is or becomes publicly known through no breach by the Receiving Party;
(b) was known to the Receiving Party without restriction before disclosure;
(c) is independently developed by the Receiving Party without use of Confidential Information; or
(d) is required to be disclosed by law or court order, provided the Receiving Party
gives prompt prior written notice where permitted and cooperates in seeking a protective order.

**7.3 Permitted Disclosures.** Each party may disclose Confidential Information to its
employees, contractors, and legal advisors who need to know and are bound by obligations
at least as protective as this Part.

**7.4 Duration.** Confidentiality obligations survive termination for five (5) years.
Obligations regarding trade secrets survive for as long as the information remains a
trade secret under applicable law.

---

## Part VIII — Warranties and Disclaimer

**8.1 Licensor Warranties.** Licensor warrants that:

  (a) Licensor has the full right, power, and authority to enter into this Agreement and
      to grant the licences herein;

  (b) to Licensor's actual knowledge as of the Effective Date, Wardex does not infringe
      any third party's copyright or registered trade secret rights; and

  (c) Wardex will perform materially in accordance with its published documentation for
      ninety (90) days following delivery ("Warranty Period"). Licensee's sole remedy for
      breach of this warranty is, at Licensor's election, correction of the
      non-conformance or a pro-rata refund of pre-paid Fees for the non-conforming period.

**8.2 Disclaimer.** EXCEPT AS EXPRESSLY SET FORTH IN SECTION 8.1, AND TO THE FULLEST
EXTENT PERMITTED BY MANDATORY APPLICABLE LAW, WARDEX IS PROVIDED "AS IS". LICENSOR
DISCLAIMS ALL OTHER WARRANTIES, EXPRESS, IMPLIED, OR STATUTORY, INCLUDING ANY IMPLIED
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND
NON-INFRINGEMENT. WARDEX IS A DECISION-SUPPORT TOOL; LICENSOR DOES NOT WARRANT THAT
WARDEX WILL PRODUCE ACCURATE, COMPLETE, OR LEGALLY SUFFICIENT RISK ASSESSMENTS. SECURITY
AND COMPLIANCE DECISIONS MADE IN RELIANCE ON WARDEX REMAIN THE SOLE RESPONSIBILITY OF
LICENSEE.

Nothing in this Section 8.2 excludes any guarantee or warranty that cannot be disclaimed
under mandatory provisions of Portuguese law, EU law, or the mandatory law of Licensee's
domicile.

---

## Part IX — Limitation of Liability

**9.1 Mutual Exclusion of Consequential Damages.** TO THE FULLEST EXTENT PERMITTED BY
APPLICABLE LAW, NEITHER PARTY SHALL BE LIABLE TO THE OTHER FOR ANY INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR IN CONNECTION WITH THIS
AGREEMENT — INCLUDING LOSS OF PROFITS, LOSS OF REVENUE, LOSS OF BUSINESS, LOSS OF DATA,
OR COST OF SUBSTITUTE SERVICES — HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

**9.2 Aggregate Liability Cap.** EXCEPT AS PROVIDED IN SECTION 9.3, EACH PARTY'S TOTAL
CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT SHALL NOT EXCEED THE
TOTAL FEES PAID OR PAYABLE BY LICENSEE TO LICENSOR IN THE TWELVE (12) MONTHS IMMEDIATELY
PRECEDING THE EVENT GIVING RISE TO THE LIABILITY.

**9.3 Unlimited Liability Carve-Outs.** The exclusions and limitations in Sections 9.1
and 9.2 shall NOT apply to, and shall in no event limit, either party's liability for:

  (a) death or personal injury caused by that party's negligence;

  (b) fraud or fraudulent misrepresentation;

  (c) wilful misconduct (dolo) or gross negligence (negligência grosseira / culpa grave),
      in accordance with Article 809.º of the Portuguese Código Civil;

  (d) infringement by Licensor of Licensee's intellectual property rights;

  (e) a party's obligations and liability arising under the GDPR and applicable national
      data protection law, to the extent that such liability cannot be limited by contract
      under applicable mandatory law; or

  (f) any other liability that cannot lawfully be excluded or limited under mandatory
      applicable law.

**9.4 Basis of the Bargain.** The parties acknowledge that the limitations in this Part IX
reflect a reasonable and negotiated allocation of commercial risk between sophisticated
business parties and form an essential element of the Agreement. Licensor would not enter
into this Agreement at the agreed Fees without them.

---

## Part X — Data Protection

**10.1 Independent Controllers.** To the extent that either party Processes Personal Data
in connection with this Agreement, each party acts as an independent controller and shall
comply with its respective obligations under the GDPR and applicable national law.

**10.2 Licensor Data Practices.** Licensor processes the following Personal Data in
connection with this Agreement: (a) names and email addresses of Licensee's designated
contacts (invoicing and support); and (b) in usage audits under Section 4.6, the count
of Authorised Developers (without identifying individuals unless Licensee provides identifiers).
Licensor's applicable privacy notice is available on written request.

**10.3 Licensee Data Practices.** Wardex generates audit logs that may contain environment
variables including user identities (e.g., `GITHUB_ACTOR`, `USER`, `WARDEX_ACTOR`).
These logs are generated on Licensee's infrastructure under Licensee's control. Licensee
is solely responsible for complying with the GDPR and applicable national law in relation
to such logs, including applicable retention limitations, lawful basis for processing,
and data subject rights.

**10.4 Data Breach Notification.** Each party shall notify the other without undue delay,
and in any event within seventy-two (72) hours of becoming aware, if it experiences a
Personal Data breach affecting Personal Data shared with or provided by the other party.

---

## Part XI — Export Controls

**11.1 Export Compliance.** Wardex includes cryptographic software (including HMAC-SHA256
and related security modules) that may be subject to export control laws and regulations,
including EU Dual-Use Regulation (EU) 2021/821 and, where applicable, the Export
Administration Regulations (EAR) of the United States Department of Commerce.

By using Wardex under this Agreement, Licensee represents and warrants that:

  (a) Licensee is not located in, incorporated under the laws of, or acting on behalf of
      a person or entity in, a country or territory subject to applicable sanctions or
      trade embargoes imposed by the EU, the United Nations, or the United States;

  (b) Licensee is not listed on any applicable denied-party, restricted-party, or
      specially designated nationals list; and

  (c) Licensee will not use Wardex in connection with any end-use prohibited by applicable
      export control law, including weapons development or mass destruction applications.

**11.2 Licensor Obligations.** Licensor will use reasonable commercial efforts to notify
Licensee of any known export restrictions that arise and affect Wardex during the
Subscription Term.

---

## Part XII — General Provisions

**12.1 Entire Agreement.** This Agreement, together with the applicable Order Form and
Schedule A, constitutes the entire agreement between the parties regarding its subject
matter and supersedes all prior agreements, understandings, and representations relating
thereto.

**12.2 Order of Precedence.** If there is a conflict between this Agreement and an Order
Form, the Order Form controls for the specific commercial terms (Tier, pricing, Authorised
Developer count, Subscription Term, and party contact details). This Agreement controls
for all other matters.

**12.3 Amendments.** Any amendment to this Agreement during an active Subscription Term
requires a written instrument signed by authorised representatives of both parties.
Updated versions of this Agreement published by Licensor shall not bind Licensee for any
then-current Subscription Term without Licensee's express written acceptance. Updated
terms shall apply to renewal Subscription Terms as set out in Section 5.1.

**12.4 Assignment.** Licensee may not assign this Agreement or any rights or obligations
hereunder without Licensor's prior written consent, not to be unreasonably withheld or
delayed. Licensor may assign this Agreement in full, without Licensee's consent, in
connection with a merger, acquisition, or sale of all or substantially all of the assets
to which this Agreement relates, provided the assignee assumes all obligations hereunder.
Licensor shall provide written notice to Licensee within thirty (30) days of any such
assignment. Any purported assignment in violation of this Section is void.

**12.5 Governing Law and Dispute Resolution.**

  (a) **Governing Law.** This Agreement is governed by the substantive law of Portugal,
      including the relevant provisions of the Código Civil (Decree-Law No. 47344/1966,
      as amended) and the regime of standard-form contracts established by Decree-Law
      No. 446/85 of 25 October 1985 (*Lei das Cláusulas Contratuais Gerais*, "LCCG"),
      as amended. This choice expressly excludes Portugal's private international law
      conflict-of-law rules. The application of this Agreement is additionally subject
      to mandatory provisions of EU law applicable to its subject matter, including
      the GDPR, EU Directive 2011/7/EU on combating late payment in commercial
      transactions, and applicable sector-specific EU directives (including NIS2 Directive
      2022/2555/EU and DORA Regulation 2022/2554/EU where applicable to the Licensee),
      which shall prevail to the extent of any inconsistency with this Agreement.

  (b) **Negotiation.** In the event of any dispute, controversy, or claim arising out of
      or relating to this Agreement, or its breach, termination, or validity ("Dispute"),
      the parties shall first attempt resolution through good-faith negotiation. Either
      party may initiate this step by written notice describing the Dispute in reasonable
      detail. If the Dispute is not resolved within thirty (30) days of such notice (or
      a longer period agreed in writing), either party may proceed to mediation.

  (c) **Mediation.** If negotiation fails, the parties shall submit the Dispute to
      non-binding mediation under the Rules of the Centro de Arbitragem Comercial da
      Câmara de Comércio e Indústria Portuguesa (CAC), seated in Lisbon. If the Dispute
      is not resolved within thirty (30) days of the commencement of mediation proceedings
      (or such extended period as the mediator recommends in writing), either party may
      initiate arbitration.

  (d) **Arbitration.** Any Dispute not resolved through negotiation or mediation shall
      be finally and exclusively settled by binding arbitration administered as follows:

      - **Rules:** CAC Arbitration Rules (current version). For Enterprise Tier disputes
        where the amount in controversy exceeds €100,000, the parties may mutually elect
        in writing to apply the ICC International Court of Arbitration Rules instead.
      - **Seat:** Lisbon, Portugal.
      - **Arbitrators:** One (1) sole arbitrator for disputes up to €50,000 (appointed
        per CAC expedited procedure); three (3) arbitrators for disputes above €50,000
        (appointed per the applicable Rules).
      - **Language:** English. If both parties expressly agree in writing, Portuguese
        may be used instead.
      - **Enforceability:** The arbitral award shall be final, binding on the parties,
        and enforceable in any contracting state to the United Nations Convention on
        the Recognition and Enforcement of Foreign Arbitral Awards (New York, 1958)
        ("New York Convention"), to which Portugal acceded with effect from
        16 January 1995.

  (e) **Urgent Interim Relief.** Notwithstanding Section 12.5(d), either party may,
      without waiving its right to arbitration, seek urgent interim, provisional, or
      conservatory relief — including injunctive relief to prevent imminent infringement
      of intellectual property rights or disclosure of trade secrets — from any court of
      competent jurisdiction.

  (f) **Mandatory Protections.** Nothing in this Section 12.5 limits any mandatory
      rights that cannot be contractually waived under the law of Licensee's domicile,
      including rights arising under any applicable national implementation of EU law
      governing rights of commercial parties in standard-form contracts.

**12.6 Notices.** All notices required or permitted under this Agreement shall be in
writing and deemed delivered: (a) by email with read-receipt confirmation to the addresses
in the Order Form (effective on the date receipt is confirmed); or (b) by registered post
or tracked courier to the addresses in the Order Form (effective on the third business
day after posting in the country of despatch). Legal notices to Licensor shall be
addressed to the contact details in the final section of this Agreement.

**12.7 Waiver.** Failure or delay by either party in exercising any right or remedy under
this Agreement shall not constitute a waiver of that right or remedy. No single or partial
exercise of any right or remedy precludes any further exercise of that or any other right
or remedy.

**12.8 Severability.** If any provision of this Agreement is found unlawful, invalid, or
unenforceable by a competent court or arbitral tribunal — including any provision found
to be a relatively prohibited clause under Decree-Law No. 446/85 — that provision shall
be modified to the minimum extent necessary to render it enforceable, or if it cannot be
so modified, excluded from the Agreement. The remainder of the Agreement shall continue
in full force and effect.

**12.9 Independent Contractors.** The parties are independent contractors. This Agreement
creates no partnership, joint venture, agency, franchise, employment, or fiduciary
relationship.

**12.10 Force Majeure.** Neither party shall be in breach of this Agreement to the extent
that performance is materially prevented by circumstances beyond that party's reasonable
control that could not have been foreseen and avoided by reasonable precautions, including:
acts of God; war; civil unrest; government action or regulation; embargoes; acts of
terrorism; epidemic or pandemic declared by a competent authority; or widespread failure
of critical internet infrastructure. The affected party shall give prompt written notice
and use commercially reasonable efforts to resume performance. If the event continues for
more than ninety (90) days, the unaffected party may terminate this Agreement on thirty
(30) days' written notice, with a pro-rata refund of pre-paid Fees for the non-performed
period.

**12.11 Headings; Interpretation.** Headings are for convenience only. "Including" means
"including without limitation." This Agreement shall be construed without any presumption
or rule requiring construction against the drafting party.

**12.12 Language.** This Agreement is executed in the English language. In any translation
dispute, the English version prevails to the extent not prohibited by mandatory applicable law.

---

## Schedule A — Licence Tiers

All Fees are exclusive of applicable VAT/IVA or equivalent indirect tax, which will be
separately itemised on invoices where applicable.

### Tier 1 — Startup

| Parameter | Value |
|---|---|
| **Annual Fee** | €2,990 / year · or €299/month (billed monthly) |
| **Authorised Developers** | Up to 10 |
| **Production Services / Pipelines** | Up to 5 |
| **Commercial Use Rights** | SaaS embedding; proprietary product distribution |
| **Support** | Email — 48-hour response SLA (business days) |
| **Updates** | Minor and patch releases during Subscription Term |
| **Eligibility** | Licensees with annual recurring revenue below €1,000,000 |

*Revenue eligibility is self-certified by Licensee. Licensor may request evidence of
revenue where eligibility is disputed. Misrepresentation of eligibility constitutes a
material breach entitling Licensor to require upgrade and recover the price difference.*

### Tier 2 — Scale

| Parameter | Value |
|---|---|
| **Annual Fee** | €9,900 / year · or €990/month (billed monthly) |
| **Authorised Developers** | Up to 50 |
| **Production Services / Pipelines** | Up to 50 |
| **Commercial Use Rights** | All Startup rights |
| **Support** | Priority email — 24-hour response SLA (business days) |
| **Updates** | All releases during Subscription Term + private roadmap access |
| **Eligibility** | No revenue restriction |

### Tier 3 — Enterprise

| Parameter | Value |
|---|---|
| **Annual Fee** | Custom — contact andre_ataide@proton.me |
| **Authorised Developers** | Unlimited |
| **Production Services / Pipelines** | Unlimited |
| **Commercial Use Rights** | All Scale rights; white-label option (negotiated separately in writing) |
| **Support** | Dedicated async channel (Slack or Teams) + named technical contact |
| **SLA** | Negotiated; 4-hour critical response available |
| **Extras** | NDA; access to redacted third-party security audit report (when available); on-site or remote onboarding; custom integration assistance |
| **Mandatory for** | Regulated sectors: financial services subject to DORA; healthcare subject to NIS2; critical infrastructure operators; any organisation requiring contractual SLA commitments |

### Internal Enterprise Use — AGPL-3.0 — No Commercial Licence Required

Organisations that run Wardex solely within their own internal CI/CD pipelines —
where all Wardex output is consumed exclusively by their own personnel and is not
offered externally as part of a commercial service — operate under AGPL-3.0 and
do not require this Commercial Licence. Internal use does not trigger AGPL-3.0's
source-disclosure requirements.

If you are uncertain whether your use case requires a Commercial Licence, contact
**andre_ataide@proton.me** for a written assessment at no charge.

---

## Contact and Order Form Enquiries

**Licensor:** André Gustavo Leão de Melo Ataíde (had-nu)
**Commercial enquiries:** andre_ataide@proton.me
**Repository:** https://github.com/had-nu/wardex
**Registered address:** 

To obtain a Commercial Licence or request an Order Form:

```
To: andre_ataide@proton.me
Subject: Wardex Commercial Licence — [Tier 1 / Tier 2 / Enterprise] — [Company Name]
```

An Order Form will be issued within three (3) business days. This Agreement is not
binding on either party until both parties have executed an Order Form.

---

*Wardex Commercial Licence Agreement — Version 1.1 — 1 March 2026*
*Copyright © 2025–2026 André Gustavo Leão de Melo Ataíde. All rights reserved.*
*Wardex™ is an unregistered trademark of André Gustavo Leão de Melo Ataíde.*

---

