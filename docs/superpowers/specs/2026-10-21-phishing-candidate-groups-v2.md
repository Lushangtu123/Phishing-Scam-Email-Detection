# Design: candidate phishing groups from headers, version 2

**Status: approved by the owner on 2026-10-21.**

- **Scope of the approval.** The six choices in the table below, plus two added rules. The design was revised
  three times after technical reviews before approval.
- **Where the full text is.** The approved text is kept, in Chinese, with the owner's local records. This file
  is its English summary for the repository.
- **Implementation.** Authorized on synthetic inputs only, up to PR and CI, not merged.
- **Not authorized:**
  - running the tool on real mail, the downloaded phishing_pot messages included;
  - reading message bodies.

## Why

Step 1's calibration plan needs phishing families that can be counted honestly. `split_by_family.py` (v1)
groups phishing by the sender key, the Reply-To key and the subject template, merged transitively.

- **The sender key.**
  - A consumer mailbox domain (Gmail and the like) uses the full address.
  - Any other domain uses its organisational domain.
- **The risk.** One organisational domain shared by many unrelated senders can glue them into one group.
  Transitive merging then pulls in more groups.

**A header-only diagnostic** on the 3,657 phishing_pot messages added after commit `49f63777` (counts only):

| Measure | Count |
|---|---|
| Largest candidate group | 2,266 messages |
| Messages in it sharing one sender organisation key | 2,114 |
| Distinct sender addresses under that key | 1,800 |

That key *may* cause false merges. It could be a shared platform, generated addresses or forged senders;
neither its identity nor any campaign membership is established.

**The opposite error matters too.** Counting every address under such a domain as its own family would
split campaigns that rotate senders. Synthetic tests can show that the code follows these rules. They
cannot show that real campaigns are neither merged nor split wrongly.

## The approved choices (2026-10-21)

| Item | Decision |
|---|---|
| K, P | K = 20, P = 0.5. Candidate screening parameters only, not a quality bar for the groups |
| Header limit | 256 KiB: at most 262,144 bytes before the blank line, the blank line not included |
| Cross-field links | Kept. A confirmed diffuse domain never merges on its own in any field; full-address links still do |
| Subject-template hubs | Reported only. A template is a hub when it appears under 20 or more distinct sender keys |
| Form | A separate new tool. v1, its ledger and the 2026-10-13 plan's split stay as they are |
| Confirmer of diffuse domains | The owner, anonymous ID `owner-01`. Domains are confirmed one by one, apart from D12's reviewer |

**The two added rules:**

1. Changing K or P needs a new policy version. It never rewrites this version's results.
2. Delegating confirmation needs the owner's explicit designation, with the delegate's identity and the
   basis recorded.

## The tool: `website/tools/phishing_candidate_groups_v2.py`

### Reading

- **Blocks.** Each file is read in 64 KiB blocks up to its first blank line (`\r?\n\r?\n`, as in v1). A
  blank line that spans two blocks is found.
- **Accepted:** at most 262,144 bytes before the blank line.
- **Excluded:** more than that, even if a blank line comes later. These are counted as `header_too_large`.
- **No blank line.** A file with no blank line, within the limit, is accepted as headers. It is counted as
  `accepted_without_blank_line`.
- **Nothing after the blank line** is decoded or parsed. Unlike v1, there is no 60,000-byte file limit:
  only headers are read.

### Copies and input identity

- **The manifest decides copies.** A trusted manifest lists each file's whole-file SHA-256 and size, made
  at download. The tool never recomputes a digest, since that would mean reading bodies. Copies are not
  decided by headers either.
- **Binding the input.**
  - The `.eml` files under the folder must be exactly the manifest's paths.
  - Each file's size (from `stat`) must match its entry.
  - Symbolic links are refused.
- **The input version** is the SHA-256 of the manifest's sorted lines. Confirmations are bound to it.
- **Remaining risk.** A same-size change to a file after the download, in headers or body, is not
  detected. Every report states it: "Original identity rests on the download-time manifest; full contents
  were not re-verified in this run."
- **Valid records** are the deduplicated originals with a parsable sender. Conservation holds: input files
  = valid records + duplicate copies + `header_too_large` + no sender address.

### Diffuse domains

- **Flagging.** A sender organisational domain is flagged when both hold, on the valid records:
  - it has at least K distinct (lower-cased) sender addresses;
  - distinct addresses ÷ its messages ≥ P.
- **Confirmation.** It approves that the domain no longer triggers merges on its own. It does not mean the
  messages belong to unrelated campaigns.
- **The confirmations file** records:
  - the confirmer;
  - the basis;
  - the input version it belongs to.

  The report records its hash.
- **Unconfirmed flags have no effect.** On input without thread links, the groups then equal v1's rules.

### Merge edges

Messages whose sender domain is a confirmed diffuse domain are class A; all others are class N.

| Edge | A–A | A–N | N–N |
|---|---|---|---|
| Same full sender address | yes | — | yes |
| Same sender key (v1's `_address_key`) | **no** | — | yes (consumer domains by full address, as in v1) |
| Same diffuse domain and subject template | yes | — | — |
| Subject template alone | **no** | **no** | yes (as in v1) |
| Same full Reply-To address | yes | yes | yes |
| Same Reply-To key, if it is not a confirmed diffuse domain | yes | yes | yes |
| A sender key meeting a Reply-To key (v1 shares one key space), if the key is not a confirmed diffuse domain | full address only | yes | yes |
| Thread: one message's Message-ID named in another's In-Reply-To or References | yes | yes | yes |

- **Large groups can still form.** Allowed edges can bridge class-A messages through a third message. Such
  groups are counted as `bridged`: their class-A messages fall apart under same-address and same-domain
  template edges alone.
- **Thread IDs.**
  - Each ID loses only outer whitespace and one pair of outer angle brackets. It must then read
    `left@right`, with no whitespace, `<`, `>` or `@` in either part. Anything else, including internal
    whitespace, is rejected.
  - Missing, empty and malformed IDs make no edge.
  - A Message-ID held by two or more different originals is ambiguous and makes no edge.
  - Over 100 References, the list's first ID and its last 99 are kept. This is the project's own trimming
    choice, not RFC 5322's, and can lose middle links. The first ID is not guaranteed to be the thread's
    root.

### Output

**The report** holds counts only:

- input and exclusion counts, and the conservation check;
- thread-ID counts;
- the diffuse domains: flagged, confirmed, unconfirmed and rejected;
- groups: their size distribution, the bridged groups and the capacity at 10 per group;
- the number of hub templates;
- for each edge type: the linking keys, the messages that carry them, and the groups that would split
  without that edge type;
- v1's rules on the same records, for comparison.

**The flagged domain values** go only to a private list for the confirmer, written outside the
repository with mode 0600.

**Errors are fixed messages,** with no path or value.

## Acceptance criteria (synthetic, fixed before the implementation)

| # | Criterion |
|---|---|
| S1 | v1 unchanged: `split_by_family.py` and its tests byte-identical; its outputs unchanged |
| S2 | A confirmed diffuse domain no longer merges five unrelated campaigns (v1: 1 group; v2: 5) |
| S3 | One campaign on a confirmed domain, with 10 addresses and one template, stays one group; unconfirmed returns to v1 |
| S3b | Different users of a consumer mailbox domain are not merged |
| S3c | Cross-field links hold for non-diffuse keys; a confirmed diffuse domain links in no field except by full address |
| S4 | Thread evidence alone joins two messages that share nothing else |
| S5 | A Reply-To on another confirmed diffuse domain does not bypass the rule; the same Reply-To address does join |
| S6 | A subject template does not cross from a class-A message to another domain |
| S7, S7b | A third message cannot bridge through templates. It can bridge through allowed edges, and that group is counted as bridged |
| S8, S8b | Unconfirmed flags equal v1 on input without thread links; thread links hold whatever the confirmation |
| S9 | Threshold boundaries (K − 1 / K, P just below / at), on deduplicated records |
| S10 | Shuffled and reversed input give a byte-identical report |
| S11–S11c | Reading boundaries, manifest-based copies, odd thread IDs |
| S12 | Counts only; flagged values only in the private list; confirmations bound to the input |
| S13 | A v1 ledger is refused as input |
| S14 | Each planted defect makes a test fail |
