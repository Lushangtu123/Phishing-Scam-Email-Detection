# Data licenses

**Status: what each source states about itself, as read on 2026-10-19.** This is an inventory, not
legal advice. The owner or legal counsel decides whether PhishGuard may use a source for a given
purpose, in particular a commercial one.

- **In scope:**
  - every public corpus that trained the served text model;
  - every reference list shipped with the deployment;
  - every public corpus used in an evaluation recorded in the [evaluation log](evaluation.md).
- **Out of scope:** the owner's own mail and text messages, and any model trained on them. They stay
  outside the repository (`AGENTS.md`).

## How this was checked

- **Read only.** Sources read:
  - license pages, dataset cards and `LICENSE` files;
  - the metadata APIs of Hugging Face, Zenodo, Mendeley Data and GitHub.

  No dataset file was downloaded for this inventory.
- **Revisions matched by hash.** The served artifact (`website/model/content_model_artifact.pkl`,
  SHA-256 `a0a503a0…1746`) records a SHA-256 for each training file. Each source matches that hash
  at the revision given below:
  - **Hugging Face:** the file's LFS SHA-256;
  - **Mendeley Data:** the SHA-256 in the file listing;
  - **Zenodo:** the record is fixed, and it publishes MD5s only. The local copies in the git-ignored
    `phishing-detection/data/` match both the record's MD5 and the artifact's SHA-256.
- **"Commercial use"** below is what the source's own statement allows. It is not a legal
  conclusion.

## Summary

1. **Whether the served model may be used commercially is unclear.** Its PhishNChips training file
   `core_emails.csv` (2,000 rows read) includes, as the dataset's own `SOURCE_LICENSES.md` records:
   - 66 rows with OpenPhish URLs, which OpenPhish allowed for academic research use;
   - 662 rows with Tranco domains, used under academic-use norms.

   The dataset card's overall license is `other`.
2. **`Phishing_Email.csv` is LGPL-3.0.**
   - It is a software license. How it applies to data, and to a model trained on that data, is
     unclear.
   - The uploader does not say where the messages come from.
3. **CEAS 2008's own terms were not found.** The curated copy on Zenodo is CC BY 4.0. The challenge's
   page returns no content.
4. **The repository is public and has no `LICENSE` file.** It holds:
   - the trained artifact;
   - a copy of the Spamhaus DROP lists, whose terms grant no license to their content.
5. **Three evaluation sources do not allow commercial use, or grant no license:**
   - phishing_pot (CC BY-NC 4.0);
   - UniqueData (CC BY-NC-ND 4.0);
   - PhishFuzzer (no license for the dataset).

   An evaluation by or for a company may need permission to use them, or must leave them out. This
   includes the DKIM design's development measurement on the phishing_pot pilot
   ([criterion 4](superpowers/specs/2026-10-15-dkim-self-verification-design.md)).
6. **Two evaluation sources have no recorded origin:**
   - the DataCon 2023 day-1 Chinese messages;
   - the local trec06c sample.

## 1. Training data of the served model

The artifact's `data_source` lists these files. Real rows were normalised, deduplicated and sampled
to 30,000 (seed 42) before training.

| Source | Revision | License stated | Commercial use, as stated | Attribution | Uncertain |
|---|---|---|---|---|---|
| `Phishing_Email.csv` from [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset). The card says it copies Kaggle's [Phishing Email Detection](https://www.kaggle.com/datasets/subhajournal/phishingemails) by user Cyber Cop | Hugging Face `34085a03`; Kaggle version 1 (2023-07-06) | LGPL-3.0, on both the card and Kaggle | Allowed by the license text, with its conditions | Keep the license notice; name the source | A software license on data; how it applies to a trained model; the messages' origin is not named |
| `CEAS_08.csv` and `Nazario.csv` from [Zenodo 8339691](https://zenodo.org/records/8339691), "Phishing Email Curated Datasets" by Champa, Rabbi and Zibran | The Zenodo record (published 2023-09-13) | CC BY 4.0 | Allowed with attribution | Cite the record's two papers (see Attribution) | CEAS 2008's own terms were not found. Nazario's own statement is CC BY 4.0 |
| `phishnchips_core.csv`, `phishnchips_legit_v5.csv` and `phishnchips_infra.csv` from [AreLit/PhishNChips](https://huggingface.co/datasets/AreLit/PhishNChips) v5.2 | Hugging Face `89afcc39` | `other`: the project's own content is MIT; third-party parts are listed in `SOURCE_LICENSES.md` | **Unclear** for `core_emails.csv` | As `SOURCE_LICENSES.md` asks (see Attribution) | `core_emails.csv` mixes sources (below) |
| `SpaPhish.csv` from [SpaPhish](https://data.mendeley.com/datasets/hz2d6gz7pc/1) by Bustio-Martínez et al. | Mendeley file `c08c152f…`, in versions 1 and 2 (DOI 10.17632/hz2d6gz7pc.1). SHA-256 `fdd74842…9cc5`, pinned in `content_model.py` | CC BY 4.0 | Allowed with attribution | Credit the authors, link the license, state the changes | Mendeley warns that third-party content in a dataset may need further permission; these are real messages. Version 5 replaced the CSV |
| 1,044 legitimate hard negatives | `content_model.py` | Written by the project | — | — | — |

**PhishNChips `core_emails.csv`**, as its `SOURCE_LICENSES.md` records:

| Rows | Source | Terms recorded |
|---:|---|---|
| 700 | PhishTank URLs | PhishTank's terms allow commercial use without charge |
| 662 | Tranco domains | Academic-use norms (Le Pochat et al., NDSS 2019) |
| 333 | Project-generated legitimate mail | MIT |
| 234 | Community GitHub phishing databases | MIT / CC BY 4.0 |
| 66 | OpenPhish URLs | Permission for academic research use, granted by email on 2026-04-06 |
| 5 | Project-generated adversarial legitimate mail | MIT |

The other two files:

- `cross_domain_legitimate_v5.csv` (333 rows) is project-generated (MIT).
- `infrastructure_phishing_expanded.csv` (54 rows) comes from the Nazario corpus (CC BY 4.0).

**Downloads are not pinned.** `content_model.py` downloads the Hugging Face files from
`resolve/main`, not from a fixed revision. The revisions above hold exactly the files the artifact
records. Pinning the URLs to them would be a separate code change.

## 2. Reference data shipped with the deployment

`vercel.json` bundles `website/data/**` with the function. The same files are in the public
repository.

| File | Source | License or terms stated | Uncertain |
|---|---|---|---|
| `ip_reputation.json`, `spamhaus_drop` (1,783 networks, fetched 2026-10-02) | Spamhaus DROP, v4 and v6 | [Terms](https://www.spamhaus.org/drop/terms/), undated: free of charge; content protected by copyright and database right; no license granted; the Spamhaus name and Spamhaus data may not be used in commercial materials | Whether a copy may sit in a public repository and a commercial product. The terms neither allow nor forbid it expressly |
| `ip_reputation.json`, `tor_exits` (1,383 addresses) | The check.torproject.org bulk exit list | The file records CC0. [Tor Metrics](https://metrics.torproject.org/about.html) states CC0 for its data | The CC0 statement does not name this list |
| `rdap_bootstrap.json` | IANA RDAP DNS bootstrap | The [IANA and IETF joint statement](https://www.iana.org/help/licensing-terms) puts protocol registries under CC0 1.0 | Low |
| `disposable_domains.json` | Curated by the project, migrated from `app.py` | — | Its earlier inputs are not recorded |
| `privacy_relay_domains.json`, `official_brands_cn.json`, `official_brands_intl.json` | Domain facts from the providers' and organisations' own pages | — | `official_brands_intl.json` holds short quotations from those pages |

**The historical benchmark** shown on the site and by `/api/metrics` comes from
[UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites) (ID 327), by
Mohammad and McCluskey, under CC BY 4.0. The page names the dataset but not its creators.

## 3. Evaluation-only sources

None of these trains the served model. Their files stay in git-ignored folders.

| Source | Revision | License stated | Commercial use, as stated | Uncertain |
|---|---|---|---|---|
| [DiFraud](https://huggingface.co/datasets/redasers/difraud), phishing subset | `f8fa04af` | MIT | Allowed | The card describes the subset as a 2020 email phishing benchmark. Its legitimate mail carries DNC, Sony and Hacking Team markers ([evaluation log](evaluation.md#5-external-public-corpora-2026-09-29)). Whether DiFraud's MIT license covers the upstream rights is unclear |
| [PhishFuzzer](https://github.com/DataPhish/PhishFuzzer) | `1e21dd4e` | **None for the dataset**: no `LICENSE` file, and none in the README. CC BY 4.0 is the license of the [paper on arXiv](https://arxiv.org/abs/2511.21448) | Not granted | The 300 manual seeds are anonymised personal and corporate submissions. The rest derive from a Kaggle set and SpamAssassin |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | `49f63777` | CC BY-NC 4.0 (the `LICENSE` at that commit) | Not allowed | Contributors are asked to remove the honeypot's address; other personal data may remain |
| [SpamAssassin easy_ham](https://spamassassin.apache.org/old/publiccorpus/readme.html) | `20030228_easy_ham.tar.bz2`, SHA-256 `2b7b6590…7438` | No license. The readme says copyright stays with the original senders | Not granted | — |
| [Nazario yearly mboxes](https://monkey.org/~jose/phishing/), 2015–2025 | Fetched 2026-09-29 | CC BY 4.0. Its README says commercial use is allowed with attribution | Allowed with attribution | The `SOURCES.txt` with per-file SHA-256s is no longer found locally |
| [marketeam/Marketing-Emails](https://huggingface.co/datasets/marketeam/Marketing-Emails) | `56377f42` | MIT; fully synthetic | Allowed | — |
| [Postmark transactional templates](https://github.com/ActiveCampaign/postmark-templates) | `fa73527a` | MIT | Allowed | — |
| [UniqueData/email-spam-classification](https://huggingface.co/datasets/UniqueData/email-spam-classification) | `f9c3f31e` | CC BY-NC-ND 4.0. The card offers commercial use by purchase | Not allowed | — |
| [lists.apache.org](https://lists.apache.org/) archives, 14 monthly mboxes from 2025 | Fetched 2026-09-29 | No license for the posts. The [ASF privacy policy](https://privacy.apache.org/policies/privacy-policy-public.html) (valid as of 2025-01-16) says lists are public and third parties may collect and process them | Unclear | Posts carry names and addresses, which are personal data |
| [SMS phishing dataset](https://data.mendeley.com/datasets/f45bkkt8pr/1) by Mishra and Soni | Mendeley version 1 (DOI 10.17632/f45bkkt8pr.1); `Dataset_5971.zip`, SHA-256 `9bbf3188…3cc3` | CC BY 4.0 | Allowed with attribution | The texts were converted from images found online, so third-party content may need further permission |
| DataCon 2023 day 1 (611 Chinese messages) | Not recorded | Not recorded | — | The owner confirms the origin |
| trec06c sample (TREC 2006 Chinese) | Not recorded | The corpus's licensed channel no longer serves it (`cormack.uwaterloo.ca/treccorpus06/`: HTTP 404 on 2026-10-19), so its agreement could not be read | — | How the local copy was obtained is not recorded |

**Correction (2026-10-19).** The [evaluation log](evaluation.md#5-external-public-corpora-2026-09-29)
said PhishFuzzer's paper "states CC BY 4.0". In fact CC BY 4.0 is the arXiv license of the paper
itself, and no license is given for the dataset. The log's table now says so.

## 4. Attribution

Is a trained model, or an evaluation report, "Adapted Material" under these licenses? That is a
legal question. The credits are given whatever the answer.

**Served model:**

- "Phishing Email Detection" by Kaggle user Cyber Cop (subhajournal), via Hugging Face
  (zefang-liu/phishing-email-dataset), under LGPL-3.0.
- A. I. Champa, M. F. Rabbi and M. F. Zibran, "Phishing Email Curated Datasets", Zenodo,
  doi:10.5281/zenodo.8339691, under CC BY 4.0. Its papers:
  - "Why phishing emails escape detection: A closer look at the failure points", ISDFS 2024;
  - "Curated datasets and feature analysis for phishing email detection with machine learning",
    ICMI 2024.
- PhishNChips v5.2 (AreLit, Hugging Face). Its URL indicators come from PhishTank (Cisco Talos),
  OpenPhish and community-maintained GitHub phishing databases. Its domain seeds come from the
  Tranco list (Le Pochat et al., NDSS 2019), and its historical phishing from the Nazario phishing
  corpus by Jose Nazario (CC BY 4.0).
- L. Bustio-Martínez et al., "SpaPhish: A Spanish Dataset for Phishing and Psychological Pattern
  Detection", Mendeley Data, version 1, doi:10.17632/hz2d6gz7pc.1, under CC BY 4.0.
- **Changes made:**
  - the text was normalised;
  - duplicates and label conflicts were removed across sources;
  - 30,000 real rows were sampled (seed 42);
  - SpaPhish was split by date;
  - the result trained a TF-IDF classifier (`content_model.py`).

**Shipped data:**

- **Spamhaus DROP:** © 2026 The Spamhaus Project SLU; the notice is kept in `ip_reputation.json`.
- **Tor bulk exit list:** The Tor Project.
- **RDAP DNS bootstrap:** IANA.

**Benchmark shown on the site:** R. Mohammad and L. McCluskey, "Phishing Websites", UCI Machine
Learning Repository, doi:10.24432/C51W2X, under CC BY 4.0.

**Evaluation reports:**

- the Nazario phishing corpus by Jose Nazario (CC BY 4.0);
- S. Mishra and D. Soni, SMS phishing dataset, doi:10.17632/f45bkkt8pr.1 (CC BY 4.0);
- DiFraud (MIT);
- marketeam/Marketing-Emails (MIT);
- Postmark templates by ActiveCampaign (MIT).

## 5. Open questions for the owner or counsel

1. **The served model.** May it be used commercially, given what `core_emails.csv` contains? Two
   options:
   - ask OpenPhish for permission and check Tranco's own terms;
   - retrain without those rows. This is a model change, with its own criteria, evaluation and
     scikit-learn pin.
2. **LGPL-3.0.** How do its conditions apply to `Phishing_Email.csv` and to a model trained on it?
3. **CEAS 2008.** What are its own terms?
4. **The repository.** Should it get a license? May the Spamhaus copy stay in a public repository,
   or should it be fetched at deploy time?
5. **A company evaluation.** Get permission for phishing_pot, UniqueData and PhishFuzzer, or leave
   them out.
6. **Origins.** Where did DataCon 2023 day 1 and the trec06c sample come from?
7. **Personal data.** Several public corpora hold personal data: the Apache lists, phishing_pot,
   SpaPhish and DiFraud. Can they be used under the company's data-protection rules?
8. **The site's UCI credit.** Should the site credit the UCI dataset's creators? That is a frontend
   change.
