# OT Sentinel — First-Impression Audit

> **Perspective**: 15-year OT security engineer, ICS/SCADA specialist.
> **Scenario**: I see this repo linked on Reddit or LinkedIn. Do I star it,
> fork it, or close the tab in 5 seconds?

---

## Executive Summary

**Overall grade: B+ (strong foundation, 3-4 critical gaps before launch)**

The rules are technically sound. The protocol coverage is impressive for an
open-source project. The documentation is thorough. But the repo makes claims
it hasn't proven yet, and it's missing the social proof and polish that
separate "interesting side project" from "production-grade community resource."

Fix the 4 critical items below, and this goes from B+ to A.

---

## What Stops Me Cold (Critical — Fix Before Launch)

### 1. The "Tested" Claim Is Currently False Advertising

This is the single biggest credibility risk.

> The README says: *"tested against a real OpenPLC + GNS3 digital twin lab."*

But every rule header says: `Tested: No (pending OpenPLC + GNS3 lab validation)`.

| What the repo claims | What the repo proves |
|---|---|
| 29 rules, lab-tested | 0 rules tested, 29 marked "Tested: No" |
| "Unique moat" — tested against real hardware | No test results, no screenshots, no evidence |

A 15-year veteran will grep for "Tested: Yes" before deploying anything.
Right now they get zero results and close the tab.

**Fix**: Run the testing guide this weekend. Flip even 8/29 rules to
`Tested: Yes`. That's enough — 8 tested rules with real OpenPLC is infinitely
more credible than 0 tested rules with a claim.

### 2. No Evidence of the Lab

You claim a digital twin exists. I don't see it.

What I want:
- A **screenshot** of the OpenPLC web interface with coils/registers visible
- A **screenshot** of a Wazuh dashboard showing an OT Sentinel alert firing
- A **terminal screenshot** showing `wazuh-logtest` matching a rule
- The actual **network diagram** rendered as a PNG, not ASCII art

Right now the README has zero images. On Reddit, posts with images get 2-3x
engagement. On LinkedIn, images are mandatory for impressions.

**Fix**: Add a `docs/lab-setup/network-diagram.png` (or even better, a
screenshot directory with 3-4 images). Embed one in the README.

### 3. Every Rule Is "Experimental"

All 29 Sigma rules say `status: experimental`. This is technically honest,
but it tells the community: "I haven't tested any of these." If you're a CISO
evaluating this for your water treatment plant, you're not deploying
experimental rules to production.

**Fix**: After testing, flip tested rules to `status: stable`. Even 8/29
stable rules changes the perception from "research project" to "deployment-ready."

### 4. Missing: The "Why This Beats Dragos/Nozomi/Claroty" Section

Every OT security engineer has heard the pitch: "Our commercial tool does
deep packet inspection for OT protocols." You need to preemptively answer:
"Why would I use this free GitHub repo instead of a $50K commercial tool?"

Right now the README has a comparison table, but it's generic. What a veteran
wants to see:

| Concern | Commercial Tool | OT Sentinel |
|---------|----------------|-------------|
| Can I see the detection logic? | No — proprietary black box | Yes — open-source XML/YAML |
| Can I customize rules? | Limited vendor UI | Full control — edit the XML |
| Does it work with my existing Wazuh? | No — requires separate platform | Yes — drop-in deployment |
| Can I audit it for backdoors? | No | Yes — Apache 2.0 |
| What does it cost? | $50K-200K/year | Free |

This table already exists partially in the README but it's buried.
Pull it up higher and make the "open-source = auditable" angle explicit.
OT security people are paranoid about supply chain — use that.

---

## What Makes Me Pause (High — Fix Before Launch)

### 5. No `SECURITY.md` or Vulnerability Reporting Process

An OT security repo without a security policy is ironic. If someone finds a
bug in a detection rule that causes false negatives, how do they report it
responsibly? Right now: open a public issue. That's a terrible answer for a
security tool.

**Fix**: Add `SECURITY.md` with:
- How to privately report detection rule bugs
- PGP key or security contact email
- Responsible disclosure timeline (30/60/90 days)

### 6. No `CODE_OF_CONDUCT.md`

Standard open-source hygiene. Missing this signals "solo project, not a
community." Every established project has one. Takes 2 minutes to add.

**Fix**: Copy the Contributor Covenant template.

### 7. No CHANGELOG or Versioning

All 29 rules are version 1.0. Fine for launch. But what happens when you
release v1.1? How do I know which rules changed? A changelog shows the
project is maintained and evolving.

**Fix**: Add `CHANGELOG.md` with an initial "v1.0.0 — Initial release" entry.
Future releases get dated entries with rule changes.

### 8. Empty Test Directories for DNP3 and IEC 104

`tests/dnp3/` and `tests/iec104/` exist but are empty. This is worse than
not having them — it promises something you haven't delivered. A veteran
browsing the repo structure will notice this instantly.

**Fix**: Either add placeholder README files ("Coming in v1.1") or add
the wazuh-logtest one-liner scripts for Tier 2 testing (30 min of work).

---

## What Would Impress Me (Medium — Nice to Have)

### 9. A Real Architecture Diagram (PNG, Not ASCII)

The ASCII art in the testing guide is functional but doesn't screenshot well.
A clean diagram (draw.io, Excalidraw, or even a well-formatted Mermaid SVG)
embedded in the README makes the repo look professional.

### 10. "Who Already Uses This" or "Who This Is For" Section

Social proof. Even if the answer is "nobody yet — be the first," state it.
Better: get one beta user (a colleague, a LinkedIn connection) to deploy it
and give a quote. One quote changes everything.

### 11. Comparison to Existing OT Open-Source Tools

There are a few: Conpot (honeypot), GRASSMARLIN (passive mapping), QuickDraw
(SNORT rules for ICS). How does OT Sentinel fit? A comparison table shows
you've done your homework and this isn't a reinvention.

### 12. A `ROADMAP.md`

Shows the project has a future. What protocols are coming next? What features?
A simple markdown table with Q3/Q4 2026 goals signals this isn't abandonware.

### 13. GitHub Issue Templates

`bug_report.md` and `feature_request.md` with pre-filled sections. Makes it
easier for strangers to contribute. Low effort, high signal.

### 14. Wireshark Screenshots in Attack Catalogs

The attack catalogs describe attack patterns in text. A Wireshark screenshot
showing the Modbus packet with the malicious function code highlighted is
worth 1,000 words. OT people live in Wireshark — they'll recognize and trust
what they see.

### 15. Real-World Attack Context

Every attack catalog entry could mention a real incident:
- MOD-001 (Coil Write): "Similar to the 2021 Oldsmar water treatment attack
  where an attacker remotely increased sodium hydroxide levels via HMI access."
- DNP3 (Broadcast): "DNP3 broadcast abuse was observed in the 2015 Ukraine
  power grid attack (Industroyer)."

Connecting rules to known incidents makes them feel necessary, not academic.

---

## What's Already Working (Don't Touch)

These things are genuinely impressive and should stay as-is:

| Element | Why It Works |
|---------|-------------|
| **Protocol coverage** | 5 protocols, 29 rules — broader than most commercial tools' free tiers |
| **Dual Wazuh + Sigma** | Covers the #1 open-source XDR AND the SIEM-agnostic standard |
| **CDB allowlists** | Shows you understand operational OT (static IPs, known devices) |
| **MITRE ATT&CK for ICS mapping** | Every rule mapped — compliance teams will love this |
| **Protocol primers** | Written for security people, not OT engineers — the right audience |
| **Frequency-based rules** | Parent/child rule pairs with thresholds — shows understanding of Wazuh internals |
| **`modbus_tap.py`** | Production-ready traffic generator — proves you can build tooling, not just rules |
| **CI/CD pipeline** | Validation on every PR — signals engineering discipline |
| **GETTING_STARTED.md** | "You don't need to be an OT engineer" — exactly right for Reddit audience |
| **Apache 2.0 license** | Industry-standard, no drama |

---

## The Reddit/LinkedIn Impressions Formula

When someone sees your post, they have 5-7 seconds to decide. Here's what
hits them, in order:

| Second | What They See | Current State | Target State |
|--------|--------------|---------------|--------------|
| 0-1s | Repo name + description | ✅ `ot-sentinel` — good | ✅ |
| 1-2s | Badges | ✅ License, rules count, CI | ✅ |
| 2-3s | First image/screenshot | ❌ None | Add OpenPLC+Wazuh alert screenshot |
| 3-4s | "What does this do?" | ✅ Clear tagline | ✅ |
| 4-5s | "Is this real or academic?" | ❌ "Tested" claim unproven | Flip 8 rules to Tested: Yes |
| 5-7s | "Should I star/fork?" | ⚠️ Missing social proof | Add Roadmap, changelog, "who uses this" |

---

## Priority Action Items (Ordered)

| # | Action | Impact | Effort |
|---|--------|--------|--------|
| 1 | Test 8 Modbus rules against OpenPLC, update headers | 🔴 Critical | 3-4 hours |
| 2 | Add 3-4 lab screenshots to README + `docs/lab-setup/` | 🔴 Critical | 30 min |
| 3 | Flip 8 tested Sigma rules from experimental → stable | 🔴 Critical | 10 min |
| 4 | Add `SECURITY.md` | 🟡 High | 10 min |
| 5 | Add `CODE_OF_CONDUCT.md` | 🟡 High | 5 min |
| 6 | Add `CHANGELOG.md` with v1.0.0 entry | 🟡 High | 10 min |
| 7 | Add placeholder READMEs to empty test directories | 🟡 High | 5 min |
| 8 | Add architecture PNG to README | 🟢 Medium | 30 min |
| 9 | Add `ROADMAP.md` | 🟢 Medium | 15 min |
| 10 | Add GitHub issue templates | 🟢 Medium | 15 min |
| 11 | Add real-world attack context to attack catalogs | 🟢 Medium | 1 hour |
| 12 | Add Wireshark screenshots to attack catalogs | 🟢 Medium | 1-2 hours |
| 13 | Get one beta user quote | 🟢 Medium | Varies |
| 14 | Add comparison to commercial OT tools (expand existing table) | 🟢 Low | 15 min |
| 15 | Add comparison to open-source OT tools (Conpot, GRASSMARLIN, QuickDraw) | 🟢 Low | 20 min |

---

## Verdict

**Would I star this repo today?** Yes — the technical content is strong enough
to earn a star even with the gaps.

**Would I deploy it to production today?** No — I need at least a few rules
proven working against real hardware.

**Would I recommend it to a colleague today?** Maybe — I'd say "keep an eye on
this, the author clearly knows their stuff, but wait for the first tested release."

**After fixing the 4 critical items?** Absolutely. This would be the most
complete open-source OT detection project on GitHub, and I'd share it myself.

---

*Audit performed against repo state as of 2026-05-29. All findings are the
opinion of a simulated 15-year OT security veteran persona.*
