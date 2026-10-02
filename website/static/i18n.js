/* ──────────────────────────────────────────────────────────────────────────
   i18n.js – UI language of the homepage and the case workspace: English
   (default) and Simplified Chinese. Runs before every other page script once
   the markup is parsed (end of <body> on index.html, the first deferred
   script on cases.html), so static text is translated before first paint.
   lang-init.js (in <head>) sets <html lang> early from the same rules. Both
   pages share the stored choice.

   This file holds the runtime and the English strings, which every page
   needs (they are the fallback and the reference for coded server text).
   The Chinese strings are i18n-zh.js, downloaded only by a visitor who uses
   Chinese: lang-init.js requests it in <head>, and setLang('zh') loads it on
   demand. PhishGuardI18n.register() receives it.

   Static markup opts in with
     data-i18n="key"                         → textContent
     data-i18n-attr="placeholder:key;title:k" → attributes
     data-i18n-html="key"                    → innerHTML (trusted <kbd> hints only)
   and keeps its English text as the no-JS fallback. Scripts call t(key, params).

   Server-provided text stays in English unless it is identified by a stable
   code (verdict, risk level, category key, feature name, mailbox status) and
   still matches the English wording below; see known(). Free-text analysis
   messages carry {code, params, msg}; see server().
   ────────────────────────────────────────────────────────────────────────── */
'use strict';
window.PhishGuardI18n = (() => {
  const STORAGE_KEY = 'phishguard-lang';
  const HTML_LANG = {en: 'en', zh: 'zh-CN'};
  const LOCALE = {en: 'en-US', zh: 'zh-CN'};

  const en = {
    // ── Document & navigation ──
    'meta.title': 'PhishGuard – Phishing Email Detector',
    'meta.description': 'Check a sender address or a full email for phishing signals, with each finding explained. PhishGuard’s scores are heuristic evidence, not a guarantee of safety.',
    'nav.skip': 'Skip to main content',
    // 404.html
    'notFound.meta.title': 'Page not found · PhishGuard',
    'notFound.code': 'Error 404',
    'notFound.title': 'Page not found',
    'notFound.lead': 'This address does not match any page. Check it for typos, or continue from one of these pages.',
    'notFound.home': 'Go to the email analyzer',
    'notFound.cases': 'Open the case workspace',
    'nav.demo': 'Live Demo',
    'nav.performance': 'Performance',
    'nav.features': 'Features',
    'nav.about': 'How It Works',
    'nav.caseLogin': 'Case login',
    'nav.caseLogin.aria': 'Case login — open the case workspace',
    'nav.theme.aria': 'Switch colour theme',
    'nav.theme.title': 'Theme: {mode}',
    'theme.mode.auto': 'auto',
    'theme.mode.light': 'light',
    'theme.mode.dark': 'dark',
    'nav.menu.open': 'Open section menu',
    'nav.menu.close': 'Close section menu',
    'nav.lang.label': 'Language: English. Switch to Simplified Chinese (中文)',
    'nav.lang.failed': 'Chinese could not be loaded. The page stays in English.',

    // ── Hero ──
    'hero.badge': 'Layered detection · rules, structure, optional ML',
    'hero.title.lead': 'Phishing email detection,',
    'hero.title.accent': 'explained.',
    'hero.subtitle': 'Analyze sender/domain risk or upload a complete email for authentication-header, identity-alignment, link, attachment, and content checks. An optional text model is evaluated with campaign-isolated splits and a phishing-recall-first threshold.',
    'hero.stat.signals': 'Sender risk signals',
    'hero.stat.layers': 'Detection layers',
    'hero.stat.auth.value': 'Auth headers',
    'hero.stat.auth.label': 'SPF, DKIM & DMARC in .eml',
    'hero.stat.ocr.value': 'OCR + QR',
    'hero.stat.ocr.label': 'Run in your browser',
    'hero.cta.check': 'Check an Email Address',
    'hero.cta.how': 'How It Works',
    'hero.chip.domain': 'Domain',
    'hero.chip.auth': 'Authentication',
    'hero.chip.links': 'Links & keywords',
    'hero.chip.structure': 'Structure',

    // ── Live demo ──
    'demo.eyebrow': 'Try it',
    'demo.title': 'Live Demo',
    'demo.lead': 'Analyze a sender address, paste subject/body text, or upload the original .eml message for the strongest available evidence.',
    'demo.tabs.aria': 'Analysis mode',
    'demo.tab.address': 'Email Address',
    'demo.tab.content': 'Email Content',
    'examples.label': 'Quick examples:',

    // ── Sender input ──
    'sender.input.aria': 'Email address to analyze',
    'sender.input.placeholder': 'Enter an email address, e.g. support@paypa1-verify.xyz',
    'sender.clear.title': 'Clear',
    'sender.clear.aria': 'Clear email address',
    'sender.analyze': 'Analyze',
    'sender.analyzing': 'Analyzing…',
    'sender.cancel': 'Cancel',
    'sender.example.disposable.title': 'Confirmed disposable',
    'sender.example.suspected': 'Suspected disposable',
    'sender.example.suspected.title': 'Suspected disposable (auto-generated username)',
    'sender.hint.slash': 'Press <kbd>/</kbd> to jump to the input',
    'sender.loading': 'Analyzing email features…',
    'sender.error.invalid': 'Enter a single email address, such as user@example.com. Use Email Content to analyze a message.',

    // ── Result actions ──
    'result.copy': 'Copy summary',
    'result.copied': 'Copied',
    'result.copyFailed': 'Copy failed',
    'result.copyAnnounce': 'Summary copied to clipboard',
    'result.download': 'Download report',
    'result.downloaded': 'Report downloaded',
    'result.downloadFailed': 'Download failed',
    'result.report': 'Report an issue',

    // ── Sender result ──
    'sender.verdict.critical': 'Critical Sender Risk',
    'sender.verdict.high': 'High Sender Risk',
    'sender.verdict.medium': 'Suspicious Sender',
    'sender.verdict.low': 'Low Sender Risk',
    'sender.riskScoreLabel': 'Sender Risk Score',
    'sender.scope': 'This address-only score does not establish that a message is safe. Check the full email, links, and authentication headers. Mailbox service type is reported separately below.',
    'sender.suspectNote': 'Sender and domain heuristics found suspicious structural patterns. This score is not a trained-model probability; verify the full message headers.',
    'sender.breakdown.summary': 'Why this score?',
    'sender.breakdown.formula': '{high} high × 28 + {medium} medium × 10 + {low} low × 3 = {raw}',
    'sender.breakdown.capped': ', capped at 100.',
    'sender.breakdown.uncapped': '.',
    'sender.breakdown.info': ' Informational notes add nothing.',
    'sender.col.evidence': 'Heuristic Evidence',
    'sender.bar.risk': 'Risk',
    'sender.col.mailbox': 'Mailbox Service Type',
    'sender.learnDisposable': 'Learn about disposable emails →',
    'sender.col.indicators': 'Risk Indicators',
    'sender.noRiskStatic': 'No risk indicators found',
    'sender.col.history': 'Sender Observation History',
    'sender.col.signals': 'Most Relevant Sender Signals',
    'sender.pill.suspected': 'Suspected Phishing',
    'sender.pill.high': '{count} high-risk',
    'sender.pill.medium': '{count} medium-risk',
    'sender.noIndicators': 'No sender risk indicators detected. Message safety is not established.',
    'sender.feature.flagged': 'Flagged feature; not a verdict',
    'sender.feature.clear': 'No flag for this feature',
    'sender.feature.mid': 'Intermediate feature value',

    // Mailbox service type (disposable_status)
    'sender.disp.alias': ' This address uses a plus tag, which is an alias and not a phishing signal.',
    'sender.disp.known.label': 'Known disposable-email provider',
    'sender.disp.known.detail': 'Provider registry match: {provider}. The individual mailbox lifetime is not known.{alias}',
    'sender.disp.relay.label': 'Privacy relay / masked address',
    'sender.disp.relay.detail': "Provider: {provider}. Privacy relays protect a user's primary address and are not phishing evidence by themselves.{alias}",
    'sender.disp.mailbox.label': 'Mailbox pattern is suspicious; lifetime unknown',
    'sender.disp.mailbox.detail': 'The username has several automatically generated characteristics. Account age and disposability cannot be confirmed from the address alone.{alias}',
    'sender.disp.mailbox.badge': 'Heuristic Detection · Not Confirmed',
    'sender.disp.domain.label': 'Disposable-style domain name; not confirmed',
    'sender.disp.domain.detail': 'Domain "{domain}" resembles a temporary-email service name but is not in the confirmed provider registry.{alias}',
    'sender.disp.none.label': 'No known disposable-provider match',
    'sender.disp.none.detail': 'Domain "{domain}" did not match the local provider registry. Account age and intent cannot be determined from the address alone.{alias}',

    // Sender observation history (sender_history_status)
    'sender.history.provider': 'Provider',
    'sender.history.caveat': "{provider} account age cannot be verified from the address or this service's retained history. ",
    'sender.history.first.label': 'First observed by this service',
    'sender.history.first.detail': '{caveat}This is retained service history, not an account-creation date.',
    'sender.history.seen.label': 'Observed previously by this service',
    'sender.history.seen.detail': '{caveat}Prior observation does not establish that this sender or message is safe.',
    'sender.history.notSeen.label': 'No prior observation in this service history',
    'sender.history.notSeen.detail': '{caveat}Absence from retained history does not prove that the provider account is new or unsafe.',
    'sender.history.raw.label': 'Available with full-message analysis',
    'sender.history.raw.detail': '{caveat}Address-only analysis does not query retained sender history. Upload a complete email to add and compare an observation.',
    'sender.history.unavailable.label': 'Observation history unavailable',
    'sender.history.unavailable.detail': 'The history service could not be checked. No sender-history conclusion was used in the risk score.',
    'sender.history.disabled.label': 'Observation history not enabled',
    'sender.history.disabled.detail': 'This service is not recording privacy-preserving sender observations. No account-age claim is available.',

    // ── Verification ──
    'verify.title': 'Email Authenticity Verification',
    'verify.checking': 'Checking mailbox verification availability…',
    'verify.desc': 'Check domain records and attempt an SMTP mailbox probe. Results may be inconclusive and do not authenticate a specific message.',
    'verify.run': 'Run Verification',
    'verify.probing': 'Probing mail server… this may take up to 10 seconds',
    'verify.section.mailbox': 'Mailbox Existence',
    'verify.step.format': 'Format Validation',
    'verify.step.mx': 'DNS / MX Records',
    'verify.step.smtp': 'SMTP Mailbox Probe',
    'verify.step.ptr': 'MX Reverse DNS (PTR)',
    'verify.section.policy': 'Email Security Policy',
    'verify.step.spf': 'SPF Record',
    'verify.badge.spf': 'Sender Policy Framework',
    'verify.step.dmarc': 'DMARC Policy',
    'verify.badge.dmarc': 'Anti-Spoofing',
    'verify.section.domain': 'Domain Intelligence',
    'verify.step.age': 'Domain Age (WHOIS)',
    'verify.rerun': 'Re-run',
    'verify.detail.formatOk': 'Address conforms to RFC 5321 format.',
    'verify.detail.formatInvalid': 'Invalid email format.',
    'verify.detail.skipped': 'Skipped.',
    'verify.detail.skippedNoMail': 'Skipped: domain declares no mail service.',
    'verify.detail.mxRecords': 'MX records: {records}',
    'verify.detail.mxPref': '{host} (pref {pref})',
    'verify.detail.noMx': 'No MX or A records found.',
    'verify.detail.smtpUnavailable': 'SMTP mailbox probing is unavailable on this deployment.',
    'verify.detail.port25': 'Port 25 appears blocked — probe skipped. Domain MX exists, mailbox unconfirmed.',
    'verify.detail.noResponse': 'Server gave no definitive response.',
    'verify.detail.ptr': 'PTR: {ptr}',
    'verify.detail.noPtr': 'No PTR record — legitimate mail servers should have reverse DNS.',
    'verify.detail.policy': 'Policy: {policy}',
    'verify.detail.noSpf': 'No SPF record found.',
    'verify.detail.noDmarc': 'No DMARC record found.',
    'verify.detail.registrar': ' · Registrar: {registrar}',
    'verify.detail.noWhois': 'WHOIS data unavailable.',
    'verify.verdict.verified': 'SMTP Accepted — The mail server accepted this address. This does not guarantee mailbox existence, delivery, or sender authenticity.',
    'verify.verdict.no_mail_service': 'No Mail Service — This domain explicitly does not accept email (Null MX). This alone is not evidence of phishing.',
    'verify.verdict.likely_invalid': 'Likely Invalid — This address probably does not exist.',
    'verify.verdict.unverifiable': 'Unverifiable — Available checks could not confirm mailbox existence. Review the DNS and SMTP details above; an unavailable or timed-out check does not prove the address is invalid.',
    'verify.verdict.suspicious': 'Suspicious — Domain was registered very recently (< 30 days). Newly registered domains are a hallmark of phishing campaigns.',
    'verify.verdict.domain_valid': 'Domain Valid — Mail-routing records exist and the available domain checks completed. The mailbox itself is not verified.',
    'verify.verdict.invalid_format': 'Invalid Format — This is not a valid email address.',
    'verify.verdict.temporarily_unavailable': 'Temporarily Unavailable — The server returned a transient error. Try again later.',
    'verify.verdict.inconclusive': 'Result inconclusive.',
    'verify.verdict.incomplete': ' Verification Incomplete — One or more checks failed, timed out, or could not run. See the individual results above.',
    'config.notice.smtpOff': 'Domain checks are enabled. SMTP mailbox probing is unavailable on this deployment, so mailbox existence cannot be confirmed.',
    'config.notice.local': 'Network-based mailbox verification is disabled in this local configuration. Enable it in the local server settings and restart the service, then reload this page.',
    'config.notice.public': 'Network-based mailbox verification is disabled on this public service. Deploy on your own computer to enable SMTP, DNS, and WHOIS checks.',
    'config.notice.unknown': 'Mailbox verification availability could not be confirmed. Reload this page to retry. Sender and message analysis remain available.',

    // ── Disposable email guide ──
    'di.title': 'What Are Disposable Email Addresses?',
    'di.sub': 'And why are they a security concern?',
    'di.definition.title': 'Definition',
    'di.definition.body': 'Disposable-email services provide shared, masked, or short-lived addresses. A provider-domain match identifies the service category but does not prove that an individual mailbox expires.',
    'di.risky.title': 'Why They Are Risky',
    'di.risky.1': 'Temporary inboxes can reduce sender accountability',
    'di.risky.2': 'They may be used to bypass account-verification policies',
    'di.risky.3': 'Privacy relays also have legitimate safety and privacy uses',
    'di.risky.4': 'A domain match is evidence, not proof of malicious intent',
    'di.examples.title': 'Known Temporary-Email Examples',
    'di.test.label': 'Test a disposable address:',

    // ── Content input ──
    'content.drop.aria': 'Screenshot upload area',
    'content.drop.help': 'Drop a screenshot or email here, or click this area and paste a screenshot (Ctrl / ⌘ + V). One file, up to 2 MiB. Then click Analyze Content.',
    'content.file.label': 'Email or image file',
    'content.file.status': 'Upload an .eml email or PNG/JPEG/WebP image, up to 2 MiB. QR and text recognition runs in your browser (up to four images). Email images are extracted locally; remote images are not loaded. Manual fields are ignored while a file is selected.',
    'content.emlGuide.summary': "How do I get the original .eml email?",
    'content.emlGuide.intro': "An original .eml keeps the sender’s real address, the real link targets and your mail service’s SPF/DKIM/DMARC results. Screenshots and copied text lose them.",
    'content.emlGuide.gmail': "Gmail (web): open the email → ⋮ (More) → Download message. After uploading, choose Gmail under “Downloaded from”.",
    'content.emlGuide.outlook': "Outlook.com / Outlook on the web: open the email → ⋯ (More actions) → Download. The Outlook desktop app saves .msg files, which are not supported; use the web version.",
    'content.emlGuide.apple': "Apple Mail (Mac): drag the email from the message list to the desktop, or choose File → Save As → Raw Message Source.",
    'content.emlGuide.webmail': "QQ Mail, NetEase 163/126 and other webmail: open the email and look for Export or Download email (.eml) in its More menu.",
    'content.emlGuide.mobile': "Mobile mail apps usually cannot export .eml; use the web version on a computer.",
    'content.emlGuide.forward': "Download the email you received, not a forwarded copy: forwarding replaces the original headers with yours.",
    'content.emlGuide.temp': "Temporary-inbox websites usually show only the rendered message, without the original headers.",
    'content.emlGuide.privacy': "An .eml contains your address and the full message. Upload only mail you are willing to have analyzed; files are limited to 2 MiB.",
    'content.col.verify': "How to verify it yourself",
    'content.verify.channel': "{organization}: don’t use this email’s links, buttons or phone numbers. Open the official app, or type {website} into your browser yourself.",
    'content.verify.phone': "Official customer service: {numbers}",
    'content.verify.source': "Source: {organization} official page",
    'content.mailbox.detected': 'This file carries {service}’s own sender check at the top. Did you download it from {service} yourself?',
    'content.mailbox.use': 'Yes, use {service}’s check',
    'content.mailbox.answerFirst': 'Answer this first: it decides whether {service}’s check can be trusted.',
    'content.mailbox.decline': 'No, or not sure',
    'content.tip.title': "A more reliable result",
    'content.tip.upload': "Upload the original email (.eml) and choose where you downloaded it (Gmail or Outlook.com). The check can then use your mail service’s own sender verification, which pasted text and screenshots lose. Genuine account and service emails are then far less often flagged.",
    'content.tip.choose': "This file carries {service}’s own sender check. If you downloaded it from {service} yourself, analyze it again with “Downloaded from: {service}”.",
    'content.tip.uploadModel': "This alert comes mainly from the text model, which often misjudges genuine modern account and notification emails. Upload the original email (.eml) and choose where you downloaded it (Gmail or Outlook.com): the check can then use your mail service’s own sender verification, which pasted text and screenshots lose, and is much more accurate.",
    'content.tip.chooseModel': "This alert comes mainly from the text model, which often misjudges genuine modern account and notification emails. This file carries {service}’s own sender check. If you downloaded it from {service} yourself, analyze it again with “Downloaded from: {service}” for a much more accurate result.",
    'content.tip.modelEml': "This alert comes mainly from the text model, which often misjudges genuine modern account and notification emails; no strong independent rule, sender or link evidence supports it. Check the sender address and links yourself before acting.",
    'content.tip.rerun': "Choose {service} and analyze again",
    'content.tip.guide': "How to get the original .eml",
    'content.remedy.title': "If you already clicked, replied or entered something",
    'content.remedy.clicked': "Only opened the link, entered nothing: close the page, and check whether the browser downloaded a file; do not open it.",
    'content.remedy.password': "Entered a password: change it right away on the official website or app (not through this email), change it on every other site that uses the same password, and turn on two-step verification.",
    'content.remedy.code': "Entered a verification code or approved a sign-in request: this is more serious. Change the password, sign out of all other devices in the account’s security settings, and review recent sign-ins. For a bank or payment account, call the number on your card or in the official app to freeze it.",
    'content.remedy.malware': "Opened an attachment, ran a program or installed remote-control software: disconnect from the internet, uninstall the remote-control software and run a full security scan. Changing passwords alone is not enough; change important passwords from another, clean device.",
    'content.remedy.money': "Sent money or gift cards: contact your bank or payment provider immediately, then report it to the police (in the US, also reportfraud.ftc.gov).",
    'content.mailbox.label': "Downloaded from",
    'content.mailbox.unknown': "Other mailbox or not sure (authentication not trusted)",
    'content.mailbox.gmail': "Gmail (original message downloaded from Gmail)",
    'content.mailbox.outlook': "Outlook.com (original message downloaded from Outlook on the web)",
    'content.mailbox.help': "Choose Gmail or Outlook.com only for an original message you downloaded from that service (Gmail: ⋮ → Download message; Outlook on the web: ⋯ → Download). The result then trusts that service’s own SPF/DKIM/DMARC check, and a verified official sender is not raised above low risk by wording alone. Choosing a service for mail it did not deliver can make a forged check look trusted.",
    'content.ocr.label': 'Image text language (OCR)',
    'content.ocr.eng': 'English',
    'content.ocr.chi': '简体中文 · Simplified Chinese',
    'content.ocr.mixed': '中英混合 · English + Chinese',
    'content.enhance.consent': 'Enhanced recognition — I agree to send this image to the configured image-processing service.',
    'content.enhance.note': 'Optional, for one PNG/JPEG/WebP image. Original image bytes are not saved with a case. Browser OCR and QR results remain available for comparison.',
    'content.semantics.consent': 'Also request model-generated image observations.',
    'content.semantics.note': 'Additional readings can be wrong. They do not change the risk verdict; verify website addresses against the original image.',
    'content.ocr.help': 'Choose the language visible in the image. English avoids unrelated Chinese characters in English screenshots. Use mixed mode for bilingual images; always check extracted text.',
    'content.subject.label': 'Subject',
    'content.subject.placeholder': 'e.g. URGENT: Your account has been suspended',
    'content.body.label': 'Email Body',
    'content.body.placeholder': 'Paste the full email body text here…',
    'content.privacy': 'Content is processed on this server. Ordinary analysis does not retain the message body or attachment content. A report is saved only if you submit one; original input is included only with your explicit consent. When sender history is enabled, a pseudonymous sender observation may be retained for abuse detection. Remove unrelated personal content before submitting an email. The Recent checks list keeps only verdicts and scores in this browser. Where domain-age lookups are enabled, the registrable domains of the sender and of up to five links (never paths or message text) are sent to the registry’s public RDAP service to look up their registration dates.',
    'content.hint.submit': '<kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Enter</kbd> to analyze',
    'content.cancelScan': 'Cancel scan',
    'content.clear': 'Clear',
    'content.analyze': 'Analyze Content',
    'content.scanning': 'Scanning…',
    'content.example.account': 'Account suspension phish',
    'content.example.lottery': 'Lottery scam',
    'content.example.newsletter': 'Legitimate newsletter',
    'content.error.pending': 'Please wait for the email file to finish loading.',
    'content.error.empty': 'Paste a subject or body, or upload an .eml or image file, before analyzing.',
    'content.error.visionUnavailable': 'Image recognition is unavailable. Reload the page.',
    'content.file.reading': 'Reading {name}…',
    'content.file.loaded': '{name} loaded — QR and text recognition will use the selected OCR language when you analyze. Manual fields are ignored.',
    'content.file.tooLarge': 'File exceeds the 2 MiB limit.',
    'content.file.empty': 'The email file is empty. Please select a message with content or attachments.',
    'content.file.unreadable': 'The email file could not be read. Please select it again.',

    // ── Content result ──
    'content.riskScore': 'Risk Score',
    'content.ml.phishing': 'Phishing',
    'content.ml.legit': 'Legit',
    'content.col.technical': 'Technical Indicators',
    'content.col.safety': 'Safety Signals Found',
    'content.col.about': 'About This Analysis',
    'content.about.body': 'This analysis combines RFC 5322 headers, sender alignment, HTML links, attachments, and explainable content signals. When a validated text model is configured, its group-isolated model score and learned threshold are added without allowing weak text evidence to erase strong structural risk.',
    'content.loading': 'Scanning email content…',
    'content.riskLabel.critical': 'Critical Risk — Very Likely Phishing',
    'content.riskLabel.high': 'High Risk — Likely Phishing',
    'content.riskLabel.highModel': 'High Risk — Model Signal Needs Review',
    'content.riskLabel.medium': 'Medium Risk — Suspicious Content',
    'content.riskLabel.mediumModel': 'Medium Risk — Model Signal Needs Review',
    'content.riskLabel.low': 'Low Risk — Minor Concerns',
    'content.riskLabel.lowVerified': 'Low Risk — Verified Official Sender',
    'content.riskLabel.lowRequested': 'Low Risk — Confirmed as Your Own Action',
    'content.riskLabel.safe': 'No Phishing Indicators Found',
    'content.riskLabel.remoteUnchecked': 'No Indicators in Inspected Text — Remote Image Unchecked',
    'content.riskLabel.incomplete': 'Analysis Incomplete — Risk Undetermined',
    'content.riskLabel.imageIncomplete': 'Image Analysis Incomplete — Risk Undetermined',
    'content.level.critical': 'Critical risk',
    'content.level.high': 'High risk',
    'content.level.medium': 'Medium risk',
    'content.level.low': 'Low risk',
    'content.level.safe': 'No indicators found',
    'content.level.unknown': 'Risk undetermined',
    'level.critical': 'critical',
    'level.high': 'high',
    'level.medium': 'medium',
    'level.low': 'low',
    'level.info': 'info',
    'level.safe': 'safe',
    'level.unknown': 'unknown',
    'content.sub.imageLimited': 'Image risk coverage is limited. Review the recognition status and extracted-text assessment in Image & QR evidence.',
    'content.sub.incomplete': 'Analysis incomplete. Review the warnings below.',
    'content.sub.attachments': 'Attachment contents were not inspected; only filenames and MIME types were checked.',
    'content.sub.inlineImages': 'Embedded image content was not inspected.',
    'content.sub.remoteImages': 'Remote image content was not inspected.',
    'content.sub.unresolvedImages': 'Unresolved image references were not inspected.',
    'content.sub.parse': 'Some message content could not be reliably parsed.',
    'content.sub.modelUnscored': 'The text model could not score this message.',
    'content.sub.ml': 'ML risk score: {score}% — {label}',
    'content.mlLabel.phishing': 'Likely Phishing',
    'content.mlLabel.legit': 'Likely Legitimate',
    'content.sub.modelOnly': 'Model-only risk signal; no independent rule, sender, or link evidence was found.',
    'content.sub.modelLed': 'Model-led risk signal; no strong independent rule, sender, or link evidence was found.',
    'content.requested.question': 'This notice is about something you would have done yourself (a code, sign-in, new account, order, job application or request), and only the text model flagged it. Are you sure you did this yourself just now?',
    'content.requested.yes': 'Yes, it was me',
    'content.requested.no': 'No, or not sure',
    'content.type.phishing': 'Looks like phishing or a scam: {tactics}.',
    'content.type.separator': ', ',
    'content.type.ad': 'Looks like advertising or marketing mail, not phishing. If you signed up with this sender you can unsubscribe; otherwise mark it as spam without clicking its links.',
    'content.type.adSuspicious': 'Looks like advertising, but scam signs remain: scams often pose as deals. Don\'t pay or sign in through its links.',
    'content.tactic.credential': 'asks for passwords or codes',
    'content.tactic.callback': 'asks you to call a number',
    'content.tactic.subsidy': 'fake subsidy or tax refund',
    'content.tactic.payment': 'asks for money, gift cards or crypto',
    'content.tactic.remote_access': 'asks for remote access',
    'content.tactic.impersonation': 'impersonates a known brand',
    'content.tactic.deceptive_link': 'disguised or suspicious links',
    'content.tactic.spoofed_sender': 'sender failed authentication',
    'content.tactic.dangerous_attachment': 'dangerous attachment',
    'content.sub.categories.one': '{count} suspicious category detected.',
    'content.sub.categories.other': '{count} suspicious categories detected.',
    'content.sub.technical.one': '{count} technical risk indicator detected.',
    'content.sub.technical.other': '{count} technical risk indicators detected.',
    'content.sub.safe': 'No indicators detected by the available checks. This does not prove the message is safe.',
    'content.sub.risk': 'Risk detected by the combined analysis. Review the evidence below.',
    'content.ml.model.generic': 'Text model',
    'content.ml.model.LogisticRegression': 'TF-IDF + Logistic Regression',
    'content.ml.model.CalibratedLinearSVC': 'TF-IDF + Linear SVM (calibrated)',
    'content.ml.model.ComplementNB': 'TF-IDF + Complement Naive Bayes',
    'content.ml.abstain.context': 'The message contains too little text, so ML classification was not applied.',
    'content.ml.abstain.rendering': 'CSS visibility or image fallback text could not be verified, so ML classification was not applied.',
    'content.ml.abstain.coverage': 'Text-model coverage was insufficient, so ML classification was not applied.',
    'content.ml.contribs.rendering': 'Uncertain HTML text was withheld; independent destinations, sender, and message-structure checks still ran.',
    'content.ml.contribs.checks': 'Rule, sender, link, and message-structure checks still ran.',
    'content.ml.verdict.phishing': 'Likely phishing',
    'content.ml.verdict.legit': 'Likely legitimate',
    'content.ml.sub': '{verdict} — model risk score {score}%',
    'content.ml.metric.recall': 'Phishing recall',
    'content.ml.metric.fnr': 'False-negative rate',
    'content.ml.metric.prauc': 'PR AUC',
    'content.ml.metric.threshold': 'Threshold',
    'content.ml.contribs.title': 'Top tokens driving the ML score',
    'content.ml.contribs.tokenTitle': 'weighted contribution: {value}',
    'content.ml.contribs.none': 'No phishing-indicative tokens found in this email.',
    'content.cat.empty': 'No suspicious keyword categories matched in this email.',
    'content.cat.count.one': '{count} signal matched',
    'content.cat.count.other': '{count} signals matched',

    // Content categories (category_results[].key); English matches app.py CONTENT_RULES.
    'category.urgency.label': 'Urgency & Pressure',
    'category.urgency.description': 'Phishing emails create artificial time pressure to prevent careful thinking.',
    'category.threats.label': 'Threats & Fear Tactics',
    'category.threats.description': 'Scammers use fear of account loss, legal trouble, or arrest to coerce victims.',
    'category.financial.label': 'Financial Lure',
    'category.financial.description': 'Promises of unexpected money or urgent payment demands are classic scam patterns.',
    'category.credential.label': 'Credential Harvesting',
    'category.credential.description': 'Requests for passwords, card numbers, SSN, or account details are major red flags.',
    'category.impersonation.label': 'Possible Brand Impersonation',
    'category.impersonation.description': 'Mentions of well-known brands alongside action requests may indicate spoofing.',
    'category.deception.label': 'Deceptive Tactics',
    'category.deception.description': 'Phrases designed to manipulate behavior, bypass skepticism, or avoid scrutiny.',
    'category.attachments.label': 'Suspicious Attachment References',
    'category.attachments.description': 'References to file attachments, especially executables or documents with macros, are a primary malware delivery vector.',
    'category.tech_scam.label': 'Tech Support / Malware Scam',
    'category.tech_scam.description': "Fake security alerts claiming your device is infected, designed to make you call fraudulent 'support' numbers.",
    'category.job_scam.label': 'Job / Money Mule Scam',
    'category.job_scam.description': 'Fake job offers, work-from-home schemes, or requests to receive and forward money on behalf of others.',
    'category.social_engineering.label': 'Social Engineering',
    'category.social_engineering.description': 'Psychological manipulation tactics that exploit trust, authority, or reciprocity to bypass judgment.',

    // Sender features (feature_breakdown[].name); English matches app.py FEATURE_INFO.
    'feature.having_ip_address.label': 'IP Address Domain',
    'feature.having_ip_address.flag': 'Domain is a raw IP address instead of a proper hostname — highly suspicious',
    'feature.having_ip_address.ok': 'Domain uses a proper hostname, not a raw IP address',
    'feature.url_length.label': 'Address Length',
    'feature.url_length.flag': 'Total email address is abnormally long — phishing addresses are often padded',
    'feature.url_length.ok': 'Email address length is within normal limits',
    'feature.shortining_service.label': 'URL Shortener Domain',
    'feature.shortining_service.flag': 'Domain belongs to a known URL shortening service — frequently abused in phishing',
    'feature.shortining_service.ok': 'Domain is not a URL shortening service',
    'feature.having_at_symbol.label': 'Multiple @ Symbols',
    'feature.having_at_symbol.flag': 'Address contains more than one @ symbol — invalid / malformed email',
    'feature.having_at_symbol.ok': 'Address has exactly one @ symbol — correct format',
    'feature.double_slash_redirecting.label': 'Double Slash in Domain',
    'feature.double_slash_redirecting.flag': "Domain contains '//' — possible redirect deception trick",
    'feature.double_slash_redirecting.ok': 'No double-slash redirect found in the domain',
    'feature.prefix_suffix.label': 'Hyphen in Domain',
    'feature.prefix_suffix.flag': 'Base domain contains a hyphen — legitimate providers rarely use hyphens',
    'feature.prefix_suffix.ok': 'Domain has no hyphens — consistent with legitimate mail providers',
    'feature.having_sub_domain.label': 'Subdomain Depth',
    'feature.having_sub_domain.flag': 'Domain has multiple subdomain levels — phishing sites use deep subdomains to impersonate brands',
    'feature.having_sub_domain.ok': 'Domain has normal subdomain depth (0–1 level)',
    'feature.https_token.label': "'http' Token in Address",
    'feature.https_token.flag': "The string 'http' appears inside the email address — a visual confusion trick",
    'feature.https_token.ok': "No misleading 'http' token found in the address",
    'feature.sslfinal_state.label': 'Recognized Provider / Domain',
    'feature.sslfinal_state.flag': 'Domain does not match the local provider or institutional-domain rules',
    'feature.sslfinal_state.ok': 'Domain matches a provider registry or institutional-domain rule; this does not authenticate the sender',
    'feature.domain_registration_length.label': 'Recognized Public Suffix',
    'feature.domain_registration_length.flag': 'Domain suffix is not recognized by the bundled Public Suffix List',
    'feature.domain_registration_length.ok': 'Domain suffix is recognized; this alone does not establish reputation',
    'feature.age_of_domain.label': 'Domain Label Length',
    'feature.age_of_domain.flag': 'Domain label is abnormally long — may be disguising a legitimate domain name',
    'feature.age_of_domain.ok': 'Domain label length is within normal range',
    'feature.dnsrecord.label': 'Digits in Domain',
    'feature.dnsrecord.flag': 'Domain name contains embedded digits — legitimate brand domains are usually letters only',
    'feature.dnsrecord.ok': 'Domain name contains no suspicious digit patterns',
    'feature.web_traffic.label': 'High-Traffic Mail Platform',
    'feature.web_traffic.flag': 'Domain is not in the high-traffic provider registry; this alone does not establish malicious intent',
    'feature.web_traffic.ok': 'Domain matches a high-traffic provider or privacy relay; this does not authenticate the sender',
    'feature.page_rank.label': 'Phishing Keywords in Domain',
    'feature.page_rank.flag': 'Domain part contains known phishing-related keywords',
    'feature.page_rank.ok': 'No phishing keywords detected in the domain',
    'feature.google_index.label': 'Phishing Keywords in Local',
    'feature.google_index.flag': 'Username (local part) contains known phishing-related keywords',
    'feature.google_index.ok': 'No phishing keywords detected in the username',
    'feature.statistical_report.label': 'Suspicious TLD',
    'feature.statistical_report.flag': 'TLD is a known high-risk or free domain extension heavily used in phishing',
    'feature.statistical_report.ok': 'TLD is not associated with high-risk or free domain registrations',
    'feature.favicon.label': 'High Digit Ratio in Local',
    'feature.favicon.flag': 'Username has an unusually high proportion of digits',
    'feature.favicon.ok': 'Username digit ratio is within normal limits',
    'feature.port.label': 'Username Randomness',
    'feature.port.flag': 'Username has high Shannon entropy — likely randomly auto-generated',
    'feature.port.ok': 'Username entropy is normal — does not appear randomly generated',
    'feature.request_url.label': 'Special Chars in Local',
    'feature.request_url.flag': 'Username contains characters outside the supported mailbox syntax',
    'feature.request_url.ok': 'Username characters are supported, including ordinary atom punctuation',
    'feature.url_of_anchor.label': 'Username Length',
    'feature.url_of_anchor.flag': 'Username exceeds 30 characters — abnormally long',
    'feature.url_of_anchor.ok': 'Username length is within normal range (≤ 30 characters)',
    'feature.links_in_tags.label': 'Brand Domain Spoofing',
    'feature.links_in_tags.flag': 'Domain appears to impersonate a well-known brand (e.g. paypal, apple)',
    'feature.links_in_tags.ok': 'No brand domain spoofing detected',
    'feature.sfh.label': 'noreply Address',
    'feature.sfh.flag': 'Sender is a noreply / no-reply / donotreply address — cannot receive replies',
    'feature.sfh.ok': 'Normal sender address — not a noreply / donotreply',
    'feature.submitting_to_email.label': 'Repeated Characters',
    'feature.submitting_to_email.flag': 'Username contains heavily repeated characters — possibly auto-generated',
    'feature.submitting_to_email.ok': 'Username has no abnormal character repetition',
    'feature.abnormal_url.label': 'Digit-Letter Mix in Domain',
    'feature.abnormal_url.flag': 'Domain mixes digits and letters suspiciously (e.g. paypa1, g00gle)',
    'feature.abnormal_url.ok': 'No suspicious digit-letter mixing detected in the domain',
    'feature.redirect.label': 'Redirect Detection',
    'feature.redirect.flag': 'Potential network-layer redirect detected',
    'feature.redirect.ok': 'No network-layer redirect detected',
    'feature.on_mouseover.label': 'Abused Country-Code TLD',
    'feature.on_mouseover.flag': 'TLD is a country code commonly abused in phishing attacks',
    'feature.on_mouseover.ok': 'TLD is not a commonly abused country-code domain',
    'feature.rightclick.label': 'Auto-Generated Username',
    'feature.rightclick.flag': 'Username matches common auto-generated patterns (short prefix + digits)',
    'feature.rightclick.ok': 'Username does not match typical auto-generated patterns',
    'feature.popupwindow.label': 'Domain Word Segments',
    'feature.popupwindow.flag': 'Domain label contains too many word segments — suspicious construction',
    'feature.popupwindow.ok': 'Domain label word structure is normal',
    'feature.iframe.label': 'Composite Risk Score',
    'feature.iframe.flag': 'Multiple risk factors detected — composite score indicates elevated phishing risk',
    'feature.iframe.ok': 'Composite risk score is low — few phishing indicators present',
    'feature.links_pointing_to_page.label': 'Valid Email Format',
    'feature.links_pointing_to_page.flag': 'Email address has unsupported or malformed mailbox syntax',
    'feature.links_pointing_to_page.ok': 'Email address matches the supported mailbox syntax',

    // ── Recent checks ──
    'recent.summary': 'Recent checks',
    'recent.note': 'Saved only in this browser: verdicts, scores and sender domains, never addresses or message text.',
    'recent.empty': 'No checks yet. Results you analyze here will be listed.',
    'recent.blocked': 'This browser is blocking local storage, so recent checks are not kept.',
    'recent.clear': 'Clear recent checks',
    'recent.cleared': 'Recent checks cleared',
    'recent.mode.sender': 'Sender',
    'recent.mode.content': 'Content',
    'recent.mode.eml': 'Email file',
    'recent.mode.image': 'Image',
    'recent.fallbackLabel': 'Result',
    'recent.time.now': 'Just now',
    'recent.time.minutes': '{count} min ago',
    'recent.time.hours': '{count} h ago',

    // ── Copy summary & reports ──
    'summary.disclaimer': 'Heuristic result from PhishGuard; it does not prove a message is safe or malicious.',
    'summary.sender.heading': 'PhishGuard sender check: {email}',
    'summary.verdict': 'Verdict: {label} ({score})',
    'summary.mailbox': 'Mailbox type: {type}',
    'summary.indicators': 'Indicators:',
    'summary.indicatorsNone': 'Indicators: none detected',
    'summary.indicatorLine': '- [{level}] {msg}',
    'summary.content.heading': 'PhishGuard content check',
    'summary.categories': 'Categories:',
    'summary.categoriesNone': 'Categories: none matched',
    'summary.categoryLine.one': '- {label} ({level}, {count} signal)',
    'summary.categoryLine.other': '- {label} ({level}, {count} signals)',
    'summary.technical': 'Technical indicators:',
    'summary.score.percent': '{score}% risk',
    'summary.score.heuristic': 'heuristic score {score}',
    'mailbox.known_disposable_provider': 'Known disposable-email provider',
    'mailbox.privacy_relay': 'Privacy relay / masked address',
    'mailbox.suspicious_mailbox_pattern': 'Suspicious mailbox pattern (not confirmed)',
    'mailbox.suspicious_domain_pattern': 'Disposable-style domain (not confirmed)',
    'mailbox.no_known_match': 'No known disposable-provider match',
    'mailbox.unknown': 'Unknown',
    'report.sender.title': 'PhishGuard sender check',
    'report.content.title': 'PhishGuard content check',
    'report.field': '- **{label}:** {value}',
    'report.sender': 'Sender',
    'report.verdict': 'Verdict',
    'report.verdictValue': '{label} ({score})',
    'report.mailbox': 'Mailbox type',
    'report.generated': 'Generated',
    'report.input': 'Input',
    'report.model': 'Text model',
    'report.modelValue': '{model} — {score}% model risk score',
    'report.indicators': 'Indicators',
    'report.noneDetected': 'None detected.',
    'report.indicatorLine': '- **{level}** — {msg}',
    'report.categories': 'Categories',
    'report.noneMatched': 'None matched.',
    'report.technical': 'Technical indicators',
    'report.warnings': 'Analysis warnings',

    // ── Requests ──
    'request.error.network': 'Cannot reach the service. Check your connection and try again.',
    'request.error.retryIn': 'Too many requests. Try again in {seconds} seconds.',
    'request.error.retryLater': 'Too many requests. Please wait before trying again.',
    'request.error.unavailable': 'This service is currently unavailable. Reload the page or try again later.',
    'request.error.unreadable': 'The service returned an unreadable response. Please try again.',
    'request.error.invalid': 'The submitted input is invalid. Please check it and try again.',
    'request.error.timeout': 'The service took too long to respond. Try again.',
    'request.cancelled': 'Analysis cancelled.',

    // ── Benchmark ──
    'perf.eyebrow': 'Benchmark',
    'perf.title': 'Archived Website Benchmark',
    'perf.lead': 'Historical course-notebook results on the UCI Phishing Websites dataset (2,211 held-out rows). These are not email-sender accuracy claims.',
    'perf.th.classifier': 'Classifier',
    'metric.Accuracy': 'Accuracy',
    'metric.Precision': 'Precision',
    'metric.Recall': 'Recall',
    'metric.F1': 'F1',
    'metric.ROC_AUC': 'ROC AUC',
    'perf.loading': 'Loading…',
    'perf.chart.title': 'Classifier Performance Comparison',
    'perf.chart.aria': 'Bar chart of accuracy, precision, recall, F1 and ROC AUC for each archived classifier; the same values are in the table above.',
    'perf.scope.title': 'Scope Matters',
    'perf.scope.body': 'The UCI model learned URL and web-page features. PhishGuard does not reuse those learned weights for sender addresses. Sender checks are explicitly labeled heuristics; email-text metrics appear only when that model is enabled.',
    'perf.best': 'Best',
    'perf.unavailable': 'Benchmark results are unavailable right now.',

    // ── Sender signals section ──
    'features.eyebrow': 'Signals',
    'features.title': 'Explainable Sender Signals',
    'features.lead': 'The sender-only mode evaluates 30 address and domain indicators. They are heuristic evidence—not probabilities learned from the UCI website dataset.',
    'bento.brand.title': 'Brand & look-alike domains',
    'bento.brand.kicker': 'High-risk heuristic',
    'bento.brand.desc': 'Flags brand names embedded in unrelated or look-alike domains—a more direct sender-risk signal than username length alone.',
    'bento.lk.sender': 'Sender',
    'bento.lk.homoglyph': 'Homoglyph · risky TLD',
    'bento.lk.brand': 'Brand',
    'bento.lk.expected': 'Expected domain',
    'bento.random.title': 'Randomized usernames',
    'bento.random.kicker': 'Six-factor pattern check',
    'bento.random.desc': 'Entropy, vowel ratio, digit mix, and repetition flag mailboxes that look machine-generated. Major providers need more factors before anything is reported.',
    'bento.random.meter': '5 of 6 randomness factors matched',
    'bento.random.caption': '5 / 6 factors · reported as suspicious, not confirmed disposable',
    'bento.tld.title': 'Risky TLDs',
    'bento.tld.kicker': 'Domain reputation',
    'bento.tld.desc': 'Free or cheap extensions that are heavily abused in phishing raise the score.',
    'bento.svc.title': 'Mailbox service type',
    'bento.svc.kicker': 'Evidence-scoped',
    'bento.svc.disposable': 'Disposable provider',
    'bento.svc.relay': 'Privacy relay',
    'bento.svc.note': 'A relay protects a real inbox and is not phishing evidence by itself.',
    'bento.provider.title': 'Known provider context',
    'bento.provider.kicker': 'Explainable heuristic',
    'bento.provider.desc': 'Recognizes common providers as context while still requiring users to inspect the complete message for spoofing and compromised-account attacks.',
    'bento.auth.title': 'Authentication & identity alignment',
    'bento.auth.kicker': 'Available with raw .eml input',
    'bento.auth.desc': 'Checks SPF, DKIM, and DMARC results plus From, Reply-To, and Return-Path domain mismatches.',
    'bento.auth.spf': 'SPF pass',
    'bento.auth.dkim': 'DKIM fail',
    'bento.auth.dmarc': 'DMARC fail',
    'bento.auth.mismatch': 'Mismatch',
    'signals.all.title': 'View all 30 sender signals',
    'signals.all.sub': 'URL / address structure · domain reputation · username patterns',
    'signals.url.title': 'URL / Address Structure',
    'signals.url.count': '8 features',
    'signals.url.1': 'IP address used as domain',
    'signals.url.2': 'Total email address length',
    'signals.url.3': 'URL shortener service domain',
    'signals.url.4': 'Multiple @ symbols',
    'signals.url.5': 'Double slash in domain',
    'signals.url.6': 'Hyphen in domain name',
    'signals.url.7': 'Subdomain depth',
    'signals.url.8': '"http" token inside address',
    'signals.domain.title': 'Domain Reputation',
    'signals.domain.count': '8 features · Highest signal',
    'signals.domain.1': 'Known legitimate mail provider',
    'signals.domain.2': 'Top-level domain type (TLD)',
    'signals.domain.3': 'Domain label character length',
    'signals.domain.4': 'Digits mixed into domain',
    'signals.domain.5': 'High-traffic mail platform',
    'signals.domain.6': 'Phishing keywords in domain',
    'signals.domain.7': 'Phishing keywords in username',
    'signals.domain.8': 'Suspicious / high-risk TLD',
    'signals.user.title': 'Username Patterns',
    'signals.user.count': '14 features',
    'signals.user.1': 'Digit ratio in username',
    'signals.user.2': 'Username randomness (entropy)',
    'signals.user.3': 'Non-standard special characters',
    'signals.user.4': 'Username length',
    'signals.user.5': 'Brand domain spoofing',
    'signals.user.6': 'noreply / system sender type',
    'signals.user.7': 'Repeated character ratio',
    'signals.user.8': 'Digit-letter mix in domain',
    'signals.user.9': 'Abused country-code TLD',
    'signals.user.10': 'Auto-generated username pattern',
    'signals.user.11': '… and composite risk features',

    // ── How it works ──
    'about.eyebrow': 'Pipeline',
    'about.title': 'How It Works',
    'about.lead': 'A layered detection pipeline designed to preserve strong phishing evidence.',
    'about.step1.title': 'Input Parsing',
    'about.step1.desc': 'Accept a sender address, subject/body text, or a complete RFC 5322 message. Raw messages expose headers, MIME parts, HTML, and attachment names.',
    'about.step2.title': 'Sender Identity Checks',
    'about.step2.desc': 'Evaluate suspicious domains, look-alike brands, risky TLDs, disposable patterns, and From / Reply-To / Return-Path alignment.',
    'about.step3.title': 'Message Structure Checks',
    'about.step3.desc': 'Inspect SPF/DKIM/DMARC results, dangerous attachments, IP and shortened URLs, and visible-link versus destination mismatches.',
    'about.step4.title': 'Explainable Content Rules',
    'about.step4.desc': 'Score urgency, credential requests, threats, obfuscation, and other suspicious behaviors. Attacker-controlled footer text cannot lower the score.',
    'about.step5.title': 'Optional Text Model',
    'about.step5.desc': 'Fit TF-IDF inside group-isolated cross-validation, keep campaign/template families together, and learn an F2-optimized phishing threshold from training folds.',
    'about.step6.title': 'Conservative Evidence Fusion',
    'about.step6.desc': 'Use the strongest credible evidence so a weak model score cannot average away clear structural or authentication risk.',
    'about.tech': 'Tech Stack',

    // ── Footer ──
    'footer.tagline': 'Explainable phishing and scam email detection. Detection supports your judgment—a low-risk result is not a guarantee of safety.',
    'footer.nav.aria': 'Footer',
    'footer.product': 'Product',
    'footer.demo': 'Live demo',
    'footer.signals': 'Sender signals',
    'footer.how': 'How it works',
    'footer.benchmark': 'Benchmark',
    'footer.analysts': 'Analysts',
    'footer.workspace': 'Case workspace',
    'footer.disposable': 'Disposable email guide',
    'footer.project': 'Project',
    'footer.docs': 'Documentation',
    'footer.changelog': 'Changelog',
    'footer.course': 'CS 166 – Information Security · Final Project',
    'footer.privacy': 'Ordinary analysis does not retain message content; a report is saved only when you submit one.',

    // ── Feedback dialog (feedback.js) ──
    'feedback.eyebrow': 'HELP IMPROVE DETECTION',
    'feedback.title': 'Report an issue',
    'feedback.close.aria': 'Close report',
    'feedback.intro': 'Tell our analysts what looks wrong. A report does not change this result.',
    'feedback.type.label': 'What happened?',
    'feedback.type.placeholder': 'Select an issue type',
    'feedback.type.false_positive': 'False positive · legitimate email flagged',
    'feedback.type.false_negative': 'False negative · suspicious email missed',
    'feedback.type.incorrect_risk': 'Risk level looks inaccurate',
    'feedback.type.incorrect_evidence': 'Evidence looks incorrect',
    'feedback.type.other': 'Other issue',
    'feedback.note.label': 'Details',
    'feedback.optional': 'optional',
    'feedback.note.placeholder': 'What should our analysts check?',
    'feedback.consent': 'Include the original input for private review.',
    'feedback.evaluation': "Also allow this email and the analyst's verdict to be used in private detection evaluation.",
    'feedback.privacy1': 'By default, we save only the risk summary, issue type and your note. The original-input checkbox also saves the address or email text you analyzed. For images, only extracted text and QR evidence are saved; the image file is never saved.',
    'feedback.privacy2': 'Evaluation is separate from private review. It requires both checkboxes, does not retrain the model automatically, and does not send your email to an external AI provider.',
    'feedback.cancel': 'Cancel',
    'feedback.close': 'Close',
    'feedback.newReport': 'Start new report',
    'feedback.submit': 'Submit report',
    'feedback.submitting': 'Submitting report…',
    'feedback.retry': 'Retry original report',
    'feedback.success': 'Report received. Reference: {id}',
    'feedback.successEdited': 'Report received. Reference: {id}. Later edits were not sent. Start a new report to submit them.',
    'feedback.retryConfirm': 'Retry the originally submitted report{source}{evaluation}? Your later edits and consent changes will not be sent.',
    'feedback.retryConfirm.withSource': ', including the original input you previously agreed to retain',
    'feedback.retryConfirm.withoutSource': ', without original input',
    'feedback.retryConfirm.evaluation': ' and allowing its use in private detection evaluation',
    'feedback.error.emlTooLarge': 'This email file exceeds the 60 KB report retention limit. Uncheck original input to submit a source-free report.',
    'feedback.error.noImageText': 'No text or QR evidence was extracted from this image. Uncheck original input to submit a source-free report.',
    'feedback.error.limits': 'Original input exceeds report limits or contains inline image data. Uncheck original input to submit a source-free report.',
    'feedback.error.unreadable': 'The server returned an unreadable response.',
    'feedback.error.notSaved': 'Report could not be saved.',
    'feedback.error.unconfirmed': ' The outcome is unconfirmed. Retry checks the original submission; later edits are not sent.',
    'feedback.error.correct': ' Correct the report and try again.',

    // ── Shared components (also loaded, untranslated, by cases.html) ──
    'confirm.continue': 'Continue',
    'confirm.cancel': 'Cancel',
    'files.error.multiple': 'Drop or paste one file at a time.',
    'files.error.type': 'Choose a PNG, JPEG, WebP image or an .eml email.',
    'files.error.size': 'Choose a nonempty file up to 2 MiB.',
    'files.error.attach': 'This browser could not attach the file. Use Choose File instead.',
    'vision.error.language': 'Choose a supported OCR language.',
    'vision.error.file': 'Choose a nonempty PNG, JPEG, WebP or EML file up to 2 MiB.',
    'vision.error.enhanceEml': 'Enhanced recognition supports one standalone image.',
    'vision.error.cancelled': 'Recognition cancelled.',
    'vision.error.tooLarge': 'File exceeds the 2 MiB limit.',
    'vision.error.timeout': 'Recognition timed out. Try a smaller image.',
    'vision.error.start': 'Recognition could not start. Reload the page or try a supported browser.',
    'vision.heading': 'Image & QR evidence',
    'vision.intro': 'Extracted in your browser; not independently verified. Recognition may miss content and does not assess malware or all image meaning. Links are shown as text and are not opened.',
    'vision.confidenceNote': 'OCR confidence measures text extraction, not a phishing probability. Successful recognition does not establish that an image is safe.',
    'vision.status.processed': 'Recognition completed',
    'vision.status.partial': 'Recognition partially completed',
    'vision.status.failed': 'Recognition failed',
    'vision.status.skipped': 'Recognition skipped',
    'vision.status.unknown': 'Recognition status unavailable',
    'vision.risk.undetermined': 'Risk undetermined',
    'vision.risk.level': 'Risk: {level}',
    'vision.summary': '{recognition} · {risk} · OCR confidence {confidence}%',
    'vision.ocrLanguage': 'OCR language: {language}',
    'vision.lang.eng': 'English',
    'vision.lang.chi_sim': 'Simplified Chinese',
    'vision.lang.mixed': 'English + Chinese',
    'vision.lang.none': 'Not recorded',
    'vision.preview.alt': 'Original uploaded image: {name}',
    'vision.preview.summary': 'Original uploaded image — compare URL characters',
    'vision.preview.enhanced': 'Enhanced recognition submitted this image for processing. This local preview and original image bytes are not saved with a case.',
    'vision.preview.local': 'This local preview is not sent to the analysis API or saved with a case.',
    'vision.urlConfidence': 'URL-like line OCR confidence: {confidence}%. Compare the address character by character with the original image; this score does not verify its spelling.',
    'vision.model.highest': 'Highest extracted-source model score',
    'vision.model.extracted': 'Extracted-text model score',
    'vision.model.score': '{label}: {score}% phishing risk. Risk assessment also uses rule and link evidence.',
    'vision.model.context': 'Too little readable text for the extracted-text model.',
    'vision.model.coverage': 'The extracted text has insufficient model coverage.',
    'vision.model.rendering': 'The extracted text could not be verified for model analysis.',
    'vision.model.unavailable': 'Extracted-text model assessment is unavailable. Review the rule and link evidence.',
    'vision.qr': 'QR payload',
    'vision.text': 'Extracted text',
    'vision.enhancement.heading': 'Additional image recognition',
    'vision.enhancement.ocr': '{engine} {version} · Additional text, not independently verified',
    'vision.enhancement.disagree': 'The extractors disagree on visible URLs. Compare both readings against the original image character by character.',
    'vision.enhancement.semantic': '{model} · Model-generated observations; not a safety verdict',
    'vision.none': 'No image observations were available. Review coverage warnings.',
    'vision.progress.extracting': 'Extracting email images…',
    'vision.progress.image': 'Reading image {index} of {total}…',
    'vision.progress.text': 'Reading {language} text…',
    'vision.progress.lang.eng': 'English',
    'vision.progress.lang.chi_sim': 'Simplified Chinese',
    'vision.progress.lang.mixed': 'English and Simplified Chinese',

    // ── Server messages (code → English template) ──
    // Identical to data/server_messages.json; server-messages.test.mjs enforces it.
    // Shown through server(), never t(): see the comment there.
    'server.sender.ip_domain': 'Domain is a raw IP address ({domain}) instead of a hostname',
    'server.sender.long_address': 'Email address is unusually long ({length} chars) — typical addresses are under 50 characters',
    'server.sender.url_shortener': 'Domain ({domain}) is a known URL shortening service frequently abused in phishing',
    'server.sender.multiple_at': 'Address contains {count} @ symbols — invalid email format',
    'server.sender.double_slash': "Domain contains '//' — possible redirect deception trick",
    'server.sender.domain_hyphen': 'Domain contains a hyphen ({domain}) — major providers typically do not use hyphens in their domains',
    'server.sender.deep_subdomains': 'Domain has {count} subdomain levels — phishing sites commonly use deep subdomains to impersonate brands',
    'server.sender.http_token': "Email address contains the token 'http' — used to create visual confusion",
    'server.sender.unrecognized_provider': 'Domain ({domain}) is not a recognized legitimate mail provider',
    'server.sender.uncommon_tld': "TLD '.{tld}' is uncommon — phishing emails often use obscure or cheap TLDs",
    'server.sender.long_domain_label': 'Domain label is unusually long ({length} characters)',
    'server.sender.domain_digits': 'Domain label contains digits ({label}) — legitimate brand domains are usually letters only',
    'server.sender.domain_keywords': 'Domain contains phishing keywords: {keywords}',
    'server.sender.username_keywords': 'Username contains phishing keywords: {keywords}',
    'server.sender.high_risk_tld': "TLD '.{tld}' is a known high-risk or free domain extension heavily used in phishing campaigns",
    'server.sender.unsupported_characters': 'Username contains unsupported mailbox characters: {characters}',
    'server.sender.long_username': 'Username is unusually long ({length} characters) — typical usernames are under 30 characters',
    'server.sender.homoglyph_brand': "Homoglyph attack detected — '{label}' uses character substitution to impersonate '{brand}' (e.g. 1→l, 0→o, vv→w)",
    'server.sender.character_substitution': "Character substitution detected in domain '{label}' — normalized to '{normalized}'",
    'server.sender.abused_cctld': "TLD '.{tld}' is a country-code domain commonly abused in phishing attacks",
    'server.sender.malformed_syntax': 'Email address has unsupported or malformed mailbox syntax.',
    'server.sender.fake_financial_business': "Domain '{domain}' follows an [abbreviation]+[financial term]+[business suffix] pattern ({breakdown}) — a known technique used to fabricate fake financial institution email domains",
    'server.sender.financial_business_combo': "Domain '{domain}' combines financial keywords ({financial}) with business entity suffixes ({suffixes}) — pattern commonly seen in financial phishing and business email compromise (BEC) domains",
    'server.sender.financial_keywords': "Domain '{domain}' contains financial-sector keywords ({financial}) on an unverified provider — verify the sender before sharing financial or personal information",
    'server.sender.business_suffix': "Domain '{domain}' uses a business entity suffix ({suffixes}) but is not a recognized or verified organization",
    'server.sender.brand_substring': "Domain '{domain}' contains the name of a well-known brand ({brands}) as a substring but is not the official domain — possible typosquatting or brand impersonation",
    'server.sender.government_keywords': "Domain '{domain}' contains government/regulatory keywords ({keywords}) but is NOT a .gov/.mil domain — likely impersonating an official body",
    'server.sender.compound_domain': "Domain label '{label}' is long ({length} chars) and appears to be a compound of multiple words — bulk phishing campaigns often generate such domains to appear business-like",
    'server.sender.random_username': "Username '{username}' matches {score}/6 randomness factors ({factors}) — the mailbox pattern looks automatically generated, but account age and lifetime cannot be confirmed",
    'server.sender.factor.entropy': 'entropy {value}',
    'server.sender.factor.vowel': 'vowel {percent}%',
    'server.sender.factor.digits': 'digits scattered',
    'server.sender.factor.unique': 'unique-ratio {percent}%',
    'server.sender.factor.no_word': 'no real word',
    'server.sender.factor.word_combo': 'unusual word combo',
    'server.sender.disposable_domain_pattern': 'Domain ({domain}) resembles a temporary-email provider name, but is not in the confirmed provider registry',
    'server.sender.known_disposable': 'Known disposable-email provider detected ({provider}). Provider category alone is not phishing evidence; mailbox lifetime is unknown.',
    'server.sender.privacy_relay': 'Privacy relay or masked-address provider detected ({provider}); this is not phishing evidence by itself.',
    'server.sender.plus_alias': 'Address uses plus subaddressing; the tag is not a phishing signal.',
    'server.sender.list_rewritten': 'Sender domain was rewritten by a mailing list (.invalid suffix); the original domain was scored.',
    'server.content.rendering_views_agree': 'Parts of this HTML may be hidden or shown only in some mail apps (Outlook-only blocks, style rules). Each version was scored and all lead to the same result, so the result stands.',
    'server.sender.authenticated_domain': 'The mailbox service verified that {domain} sent this message (DMARC and DKIM); how its addresses are named (role words, subdomains, random-looking names) is shown but not scored. Links, content and lookalike checks still apply.',
    'server.sender.service_domain': 'The address is on {organization}\'s own domain ({domain}), so how it is named (role words, subdomains, random-looking names) is shown but not scored. This does not prove the service sent it: choose the mailbox (Gmail or Outlook) the message was downloaded from to check its authentication. Links, content and lookalike checks still apply.',

    'server.content.hidden_text_padding': 'Large hidden text block accompanies an image-dominant linked message; the visible message differs substantially from its hidden text. Review the image and destination manually.',
    'server.content.password_form': 'Embedded HTML form contains a password field; inspect the submission destination before entering credentials.',
    'server.content.attachment_account_lure': "The attachment says your account, your access or a payment is restricted, on hold or compromised, asks you to verify or sign in, and links to {domain}, which is neither the sender's domain nor a listed official one. Sign in only through the address or app you normally use.",
    'server.content.fine_lure': "A notice says you have an unpaid fine or toll, and its link leads to {host}, which is neither the sender's site nor a government one. Check fines and tolls only on the official website or app you already know.",
    'server.content.delivery_lure': "A delivery notice asks you to pay a shipping or customs fee, or to correct your address, through a link to {host}, which is neither the sender's site nor a listed carrier's. Check parcels only on the carrier's own website or app.",
    'server.content.callback_request': "Asks you to call {number} to cancel, dispute or refund a charge; callback scams use fake support numbers. Call only the number on the organization's official website, app or card.",
    'server.content.mailbox_lure': 'A notice says your mailbox is full, blocked, expiring, being upgraded or holding back your mail, and its link to fix it leads to a site that is neither the sender\'s nor a known provider\'s. Sign in only through the address you normally use for your mail.',
    'server.content.subsidy_lure': 'A subsidy, allowance or tax-refund notice pressures you to claim it at once or by scanning a code. Government bodies and employers do not pay out this way by email.',
    'server.content.requested_notice': 'You confirmed this notice is about something you did yourself, so a text-model alert alone is not treated as phishing. Still check that the sender and any link belong to the service, and never share a code with anyone.',
    'server.content.unrequested_notice': 'You did not do what this notice describes, or are not sure. An unexpected code, sign-in, new account, order or application notice can mean someone is using your account, or that the message is phishing: don\'t use its links; open the service\'s own site or app instead.',
    'server.content.pressured_credential_request': 'Direct credential request combined with urgency and threats; verify through an independent channel.',
    'server.content.sensitive_request.one_time_code': "Asks you to send, reply with or read out a one-time or verification code; genuine services only ask you to enter it on their own site or app.",
    'server.content.sensitive_request.password_pin': "Asks you to send or share a password or PIN; legitimate organizations never ask for these by email.",
    'server.content.sensitive_request.recovery_secret': "Asks for backup codes, a recovery or seed phrase, or a private key; anyone with these can take over the account or wallet.",
    'server.content.sensitive_request.gift_card': "Asks you to buy gift cards or send their numbers; gift cards are a common scam payment method.",
    'server.content.sensitive_request.crypto_transfer': "Asks you to move funds or crypto to a 'new', 'safe' or 'secure' wallet or account; no bank or exchange asks this.",
    'server.content.sensitive_request.remote_access': "Asks you to install remote-access software or share your screen; this lets someone control your device.",
    'server.content.shortened_urls': 'Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain',
    'server.content.exclamation_marks': 'Excessive exclamation marks ({count}) — emotional manipulation tactic common in scam emails',
    'server.content.capitalization': 'Excessive capitalization ({percent}% uppercase) — used to simulate alarm and urgency',
    'server.content.subject_question_marks': 'Multiple question marks in subject line ({count}) — manipulative rhetorical device',
    'server.content.url_count': 'Unusually high number of URLs ({count}) — suggests bulk phishing template',
    'server.content.generic_greeting': 'Generic impersonal greeting (Dear Customer/User/Valued Member) — legitimate services address you by name',
    'server.content.large_amounts': 'Implausibly large monetary amounts mentioned: {amounts} — hallmark of advance-fee and lottery scams',
    'server.content.generic_cta': "Generic call-to-action phrases used {count}× ('click here', 'click now') — legitimate emails use descriptive link text",
    'server.content.regional_phrasing': 'Regional or formal English phrasing observed: "{phrase}"; not included in the risk score.',
    'server.content.regional_phrasing_more': 'Regional or formal English phrasing observed: "{phrase}"...; not included in the risk score.',
    'server.content.obfuscation': 'Character substitution / homoglyph obfuscation detected for: {brands} — e.g. P@yP@l, Amaz0n — used to evade spam filters',
    'server.content.category': '{label}',
    'server.content.nested_category': '{label} — {matched}',

    'server.link.obfuscated_scheme': 'Link uses an obfuscated hxxp/hxxps destination scheme.',
    'server.link.malformed_target': 'Link contains a malformed destination that could not be safely parsed.',
    'server.link.unsafe_scheme': 'Link uses an unsafe destination scheme ({scheme}:).',
    'server.link.url_userinfo': 'Link destination uses URL userinfo before the real host, a common trusted-domain deception technique.',
    'server.link.ipfs_gateway': "Link destination ({host}) is an IPFS gateway: content-addressed pages there cannot be taken down by the brand they imitate and are common in phishing.",
    'server.link.ip_host': 'Link destination uses an IP address instead of a domain name; inspect it before opening.',
    'server.link.display_mismatch': 'Link display domain ({display_host}) does not match the actual destination ({host}).',
    'server.link.idn_confusable': 'Link destination ({host}) is an IDN/confusable lookalike for {brand}.',
    'server.link.brand_lookalike': 'Link destination ({host}) is a noncanonical lookalike for {brand}.',
    'server.link.file_share_elsewhere': "The message says files were shared with you through {service}, but its download or open button leads to another site, {host}. Open shared files from the service's own website or app.",
    'server.sender.recently_registered': "The sender's domain {domain} was registered on {date}, {days} days ago (the registry's RDAP record). Phishing often uses newly registered domains; established organisations send from long-held ones.",
    'server.link.recently_registered': "The link domain {domain} was registered on {date}, {days} days ago (the registry's RDAP record). Phishing pages are often hosted on newly registered domains.",
    'server.link.user_content_action': 'A button asking you to sign in, or to verify or update your account or payment, leads to a document, form or shared file that anyone can publish on a trusted platform. Companies do not collect account or payment details there.',
    'server.link.credential_collection_host': 'Link destination ({host}) combines credential and collection wording.',
    'server.link.sensitive_host': 'Link destination ({host}) uses account-related wording on an unrecognized domain; this alone does not establish phishing.',

    'server.structure.platform_relay': "Sent through {organization}'s own servers ({domain}) on behalf of another user: a share, invitation, comment or similar notice. The platform is genuine, but the document, message and links come from that user, so this is not treated as an official message.",
    'server.structure.verified_official_sender': "Verified sender: a trusted DMARC pass shows this message came from {organization}'s own domain ({domain}). Its links and requests are still checked.",
    'server.structure.brand_display_name': "Protected brand identity '{brand}' is displayed from an unrelated domain ({domain}).",
    'server.structure.idn_sender_domain': 'Sender domain ({domain}) is a Unicode/IDN confusable for {brand}.',
    'server.structure.no_visible_recipient': 'No visible To or Cc recipient is present; the message may have used Bcc.',
    'server.structure.self_addressed': 'Self-addressed message: a From mailbox also appears in To or Cc.',
    'server.structure.sending_server': "Your mail service received this message from the server at {ip}. This is the sending server, not the sender's own device.",
    'server.structure.sending_server_unverified': "The topmost Received header names the sending server {ip}. Choose the mailbox you downloaded the message from to confirm that your mail service wrote it.",
    'server.structure.sending_server_tor': "The sending server {ip} is a Tor exit node on the Tor Project's list of {date}. The list describes that day, not the day the message was sent.",
    'server.structure.sending_server_drop': "The sending server {ip} is in a network that Spamhaus lists as run by spammers or criminals ({listing}, DROP list of {date}).",
    'server.structure.originating_ip_tor': "The X-Originating-IP header, which the sender can write, names a Tor exit node: {ip} (Tor Project list of {date}).",
    'server.structure.originating_ip_drop': "The X-Originating-IP header, which the sender can write, names {ip}, in a network that Spamhaus lists as run by spammers or criminals ({listing}, DROP list of {date}).",
    'server.structure.recipient_domain_display': "The sender's display name shows your own domain ({domain}), but the message comes from another domain. Attackers pose as your organization's mail or IT team this way.",
    'server.structure.routing_mismatch': '{header} domain ({domain}) differs from From domain candidates ({from_domains}). Routing differs; this alone does not establish impersonation.',
    'server.structure.arc_sealed_results': 'No mailbox was chosen, but the sealed authentication record from {domain} (ARC) was verified with its published key, so its checks of this message were used.',
    'server.structure.auth_failed': 'Message authentication failed: {mechanisms}.',
    'server.structure.auth_partial_failure': 'One authentication mechanism failed: {mechanisms}.',
    'server.structure.dangerous_attachment': 'Potentially dangerous attachment: {filename}.',
    'server.structure.archive_attachment': 'Archive attachment requires inspection before opening: {filename}.',

    'server.prefix.sender': 'Sender: {text}',
    'server.prefix.pdf_attachment': 'PDF attachment link: {text}',
    'server.prefix.docx_attachment': 'Word attachment link: {text}',
    'server.prefix.docx_text': 'Word attachment: {text}',
    'server.prefix.pdf_text': 'PDF attachment: {text}',
    'server.prefix.attached_message': 'Attached message: {text}',
    'server.prefix.image': 'Image ({name}): {text}',
    'server.prefix.image_recognition': 'Image recognition: {text}',

    'server.warning.mso_conditional': 'MSO conditional content has client-dependent rendering; analysis is incomplete.',
    'server.warning.malformed_html': 'Malformed HTML required recovery; analysis is incomplete.',
    'server.warning.link_unparsed': 'A link destination could not be reliably parsed; analysis is incomplete.',
    'server.warning.hidden_html_text': 'Hidden HTML text was excluded from text scoring; visual rendering was not fully verified, so analysis is incomplete.',
    'server.warning.stylesheet_visibility': 'A stylesheet may hide or reveal text; CSS rendering was not verified, so the affected text-model view was not scored.',
    'server.warning.inline_css_visibility': 'Inline CSS may conceal text; its rendering was not verified, so the affected text-model view was not scored.',
    'server.warning.possibly_invisible_text': 'Some text may be too small or faint to read, the same color as its background, clipped, off screen, or hidden in Outlook; its rendering was not verified, so the affected text-model view was not scored.',
    'server.warning.image_alt_fallback': 'Image alternative text may be shown when an image is unavailable; that rendering was not verified, so the affected text-model view was not scored.',
    'server.warning.mime_alternative_limit': 'MIME alternative view limit reached; not every rendered version was model-scored. Analysis is incomplete.',
    'server.warning.mime_alternative_model': 'At least one MIME alternative could not be model-scored; analysis is incomplete.',
    'server.warning.inline_images': 'Embedded image content was not inspected; analysis is incomplete.',
    'server.warning.remote_images': 'Remote image content was not inspected; analysis is incomplete.',
    'server.warning.unresolved_images': 'Unresolved image references were not inspected; analysis is incomplete.',
    'server.warning.han_text': 'Substantial Han-script text detected; language-specific phishing checks are limited and this content may not be fully evaluated.',
    'server.warning.model_insufficient_context': 'The message contains too little text for reliable model scoring; ML classification was not applied.',
    'server.warning.model_insufficient_coverage': 'Text model feature coverage is insufficient; ML classification was not applied.',
    'server.warning.attachment_unreadable': 'A PDF or Word attachment could not be read; its text and links were not checked. Analysis is incomplete.',
    'server.warning.attachments_uninspected': 'Attachment content was not inspected; only filenames and MIME types were checked. Analysis is incomplete.',
    'server.warning.duplicate_mime_headers': 'Duplicate MIME headers ({headers}) are ambiguous; bounded alternate inspection, analysis is incomplete.',
    'server.warning.mime_candidate_limit': 'MIME candidate limit reached; additional interpretations were not inspected.',
    'server.warning.opaque_eml_attachment': 'Opaque .eml attachment was not parsed as an encapsulated message; analysis is incomplete.',
    'server.warning.mime_decoding_fallback': 'MIME text decoding required a fallback or replacement; analysis may be incomplete.',
    'server.warning.mime_resource_limit': 'MIME parser resource limit reached; only outer headers were inspected, body and attachments were not analyzed. Analysis is incomplete.',
    'server.warning.header_unparsed': '{header} header could not be parsed; raw value preserved, analysis is incomplete.',
    'server.warning.duplicate_header': 'Duplicate {header} headers are ambiguous; all candidates inspected, analysis is incomplete.',
    'server.warning.attached_message_empty': 'Attached message has no analyzable content; analysis is incomplete.',
    'server.warning.mime_malformed': 'MIME structure is incomplete or malformed ({defects}); analysis may be incomplete.',
    'server.warning.attached_message_encoded': 'Transfer-encoded attached message was not inspected; analysis is incomplete.',
    'server.warning.attached_message_unparsed': 'Attached message could not be parsed; analysis is incomplete.',
    'server.warning.attached_message_limit': 'Attached-message depth/count limit reached; analysis is incomplete.',
    'server.warning.auth_results_incomplete': 'Authentication-Results syntax is incomplete; authentication claims require review.',
    'server.warning.visual_text_limit': 'Email text exceeded the visual submission text limit; analysis is incomplete.',
    'server.warning.visual_independent_sources': 'OCR and each distinct QR payload were assessed independently. Risk and rule scores retain the strongest individual assessment; the model score, when available, is the highest individual source score.',
    'server.warning.visual_unverified': 'Image evidence was extracted in the browser and is not independently verified. OCR and QR recognition may miss content; image safety and malware were not assessed.',
    'server.warning.ocr_verify_urls': 'Verify website addresses against the original image character by character. OCR can confuse 1/l/I or 0/O and break URL punctuation, even with high confidence. The original OCR text is preserved; no address spelling has been verified.',
    'server.warning.enhanced_failed': 'Enhanced recognition failed; browser OCR and QR results were retained.',
    'server.warning.enhanced_unverified': 'Additional recognition is unverified; original browser text and QR payloads are preserved.',
    'server.warning.enhanced_model_output': 'Model-generated observations and URLs do not establish legitimacy and do not change the risk verdict.',

    'server.safety.unsubscribe': 'Contains unsubscribe link — typical of legitimate bulk emails',
    'server.safety.privacy_policy': 'Mentions privacy policy — sign of compliance',
    'server.safety.terms_of_service': 'References terms of service',
    'server.safety.terms_and_conditions': 'References terms and conditions',
    'server.safety.opt_out': 'Provides opt-out option',
    'server.safety.not_requested': 'Acknowledges you may not have requested this',
    'server.safety.contact_information': 'Provides official contact information',
    'server.safety.copyright': 'Contains copyright notice',
    'server.safety.sender_system': 'Identifies sender system transparently',
    'server.safety.web_version': 'Provides web version link — common in legitimate newsletters',
    'server.safety.preferences': 'Offers subscription preference management',
    'server.safety.receiving_reason': 'Explains why the email was sent',
    'server.safety.subscription_consent': 'Acknowledges subscription consent',
    'server.safety.named_greeting': 'Personalized greeting (legitimate systems use names)',
    'server.safety.greeting': 'Personalized greeting',

    'server.verify.format_invalid': 'Enter a single supported email address with an unquoted ASCII local part and a valid domain.',
    'server.verify.dns_timeout': 'DNS lookup timed out or was unavailable.',
    'server.verify.dns_unavailable': 'DNS lookup was unavailable.',
    'server.verify.null_mx': 'Domain publishes Null MX: it does not accept email. This is not evidence of phishing.',
    'server.verify.invalid_null_mx': 'Invalid mixed or nonzero-preference Null MX records; mail service is inconclusive.',
    'server.verify.domain_not_found': 'Domain does not exist in DNS.',
    'server.verify.address_record_fallback': 'No MX record found; domain has an {record_type} record — using domain directly.',
    'server.verify.no_mail_records': 'Domain has no MX, A, or AAAA records.',
    'server.verify.deadline_after_dns': 'Verification deadline reached after DNS lookup.',
    'server.verify.check_busy': 'Verification capacity is busy; this check was not run.',
    'server.verify.check_failed': 'Verification check failed; result unavailable.',
    'server.verify.smtp_disabled': 'SMTP mailbox probing is unavailable on this deployment.',
    'server.verify.smtp_disabled_reason': 'SMTP mailbox probing is unavailable on this deployment; domain evidence does not prove that the mailbox exists.',
    'server.verify.smtp_timeout': 'SMTP probe timed out.',
    'server.verify.smtp_port_blocked': 'Port 25 appears blocked by your network. MX records exist, so the domain is real, but mailbox existence cannot be confirmed.',
    'server.verify.smtp_non_public_target': 'SMTP target for {host} is non-public or could not be validated.',
    'server.verify.smtp_accepted': 'Mail server accepted the address (SMTP {smtp_code})',
    'server.verify.smtp_no_such_mailbox': 'Mail server reports no such mailbox (SMTP {smtp_code}): {response}',
    'server.verify.smtp_policy_rejected': 'Policy rejection does not establish mailbox existence (SMTP {smtp_code}): {response}',
    'server.verify.smtp_mailbox_full': 'Mailbox full; not evidence of a nonexistent address (SMTP {smtp_code}): {response}',
    'server.verify.smtp_temporary_error': 'Server returned a temporary error (SMTP {smtp_code}) — try again later',
    'server.verify.smtp_inconclusive': 'Mailbox existence is inconclusive (SMTP {smtp_code}): {response}',
    'server.verify.smtp_connect_failed': 'Cannot connect to {host}:25 — {error}',
    'server.verify.smtp_disconnected': 'Server disconnected unexpectedly — {error}',
    'server.verify.smtp_connection_timeout': 'Connection to {host} timed out after {seconds}s',
    'server.verify.smtp_network_error': 'Network error: {error}',
    'server.verify.smtp_error': '{error}',
    'server.verify.spf_strict': 'Strict policy (-all): unauthorized senders are rejected.',
    'server.verify.spf_softfail': 'Soft-fail policy (~all): unauthorized senders are flagged but not blocked.',
    'server.verify.spf_neutral': 'Neutral policy (?all): no enforcement — spoofing possible.',
    'server.verify.spf_open': 'Open policy (+all): ANY server may send — high spoofing risk!',
    'server.verify.spf_unclear': 'SPF record found but enforcement policy is unclear.',
    'server.verify.spf_missing': 'No SPF record — this domain is vulnerable to email spoofing.',
    'server.verify.no_txt_records': 'No TXT records found for domain.',
    'server.verify.dns_error': 'DNS error: {error}',
    'server.verify.spf_error': 'SPF check error: {error}',
    'server.verify.spf_timeout': 'SPF check timed out.',
    'server.verify.dmarc_reject': 'p=reject: domain requests rejection of DMARC-failing messages.',
    'server.verify.dmarc_reject_partial': 'p=reject (requested for {pct}% of messages): domain requests rejection of DMARC-failing messages.',
    'server.verify.dmarc_quarantine': 'p=quarantine: domain requests quarantine of DMARC-failing messages.',
    'server.verify.dmarc_quarantine_partial': 'p=quarantine (requested for {pct}% of messages): domain requests quarantine of DMARC-failing messages.',
    'server.verify.dmarc_none': 'p=none: monitoring only — no enforcement requested.',
    'server.verify.dmarc_missing': 'No DMARC record at _dmarc.{domain} — no anti-spoofing policy set.',
    'server.verify.dmarc_not_found': 'No DMARC record at _dmarc.{domain}.',
    'server.verify.dmarc_error': 'DMARC check error: {error}',
    'server.verify.dmarc_timeout': 'DMARC check timed out.',
    'server.verify.age_very_new': 'Domain is only {days} days old — newly registered domains are a major phishing red flag.',
    'server.verify.age_new': 'Domain is {days} days old (~{months} months) — relatively new, proceed with caution.',
    'server.verify.age_under_year': 'Domain is {days} days old (< 1 year) — moderately established.',
    'server.verify.age_established_one': 'Domain registered {date} ({years} year old) — well-established.',
    'server.verify.age_established': 'Domain registered {date} ({years} years old) — well-established.',
    'server.verify.age_no_date': 'WHOIS returned no creation date for this domain.',
    'server.verify.age_failed': 'WHOIS lookup failed or data unavailable: {error}',
    'server.verify.age_timeout': 'WHOIS lookup timed out.',
    'server.verify.ptr_found': 'MX server {ip} → PTR: {ptr}',
    'server.verify.ptr_missing_ip': 'No PTR record for MX server {ip} — legitimate mail servers almost always have reverse DNS configured.',
    'server.verify.ptr_missing': 'No PTR record for MX server — legitimate mail servers almost always have reverse DNS configured.',
    'server.verify.ptr_lookup_error': 'PTR lookup error: {error}',
    'server.verify.ptr_error': 'PTR check error: {error}',
    'server.verify.ptr_timeout': 'PTR check timed out.',

    // ── Case workspace (cases.html, cases.js) ──
    'cases.badge.feedback': 'USER FEEDBACK',
    'cases.basis.external_verification': 'External verification',
    'cases.basis.report_only': 'Reporter claim only',
    'cases.basis.retained_message': 'Retained message',
    'cases.capacity.advice': 'Ask the administrator to archive and verify closed records before removing any. Closing a record does not free space.',
    'cases.capacity.aria': 'Workspace capacity',
    'cases.capacity.cases': 'Cases',
    'cases.capacity.disabled': '{label}: not configured.',
    'cases.capacity.feedback': 'User feedback',
    'cases.capacity.limited': '{label}: {used} / {limit} stored · {remaining} remaining.',
    'cases.capacity.unavailable': '{label}: capacity unavailable. Refresh to check again.',
    'cases.capacity.unlimited': '{label}: {used} stored · no application count limit.',
    'cases.capacity.warning.cases.full': 'Case storage is full.',
    'cases.capacity.warning.cases.near': 'Case storage is nearing capacity.',
    'cases.capacity.warning.feedback.full': 'Feedback storage is full.',
    'cases.capacity.warning.feedback.near': 'Feedback storage is nearing capacity.',
    'cases.compose.body': 'Email body',
    'cases.compose.bodyPlaceholder': 'Paste the message you want to investigate',
    'cases.compose.cancelScan': 'Cancel scan',
    'cases.compose.close': 'Close new case form',
    'cases.compose.dropHint': 'Drop a screenshot or email here, or click this area and paste a screenshot (Ctrl / ⌘ + V). One file, up to 2 MiB.',
    'cases.compose.dropzone': 'Screenshot upload area',
    'cases.compose.eyebrow': 'CAPTURE EVIDENCE',
    'cases.compose.newFromDraft': 'Start a new case from draft',
    'cases.compose.ocrHelp': 'Choose the language visible in the image. Use mixed mode for bilingual images and always check the extracted text.',
    'cases.compose.privacy': 'Saving retains extracted email text, addresses, detection evidence and review history in your team\'s private storage. Original attachment bytes are not saved. Submit only emails you are authorized to retain.',
    'cases.compose.subject': 'Subject',
    'cases.compose.subjectPlaceholder': 'Email subject',
    'cases.compose.submit': 'Analyze & create case',
    'cases.compose.title': 'Create an investigation',
    'cases.compose.upload': 'Or upload an email or image',
    'cases.compose.uploadHelp': '.eml / PNG / JPEG / WebP · QR and OCR run in your browser, up to four images. Remote images are not loaded.',
    'cases.confirm.retry': 'Retry the original case submission? Only the original message and extracted evidence will be sent. Your later edits will stay here for a separate case.',
    'cases.confirm.retryLabel': 'Retry original',
    'cases.confirm.saveOpinion': 'Save this structured Jev opinion to case history for all workspace analysts? It will remain after the 24-hour cache expires. Risk and human verdict will not change.',
    'cases.confirm.saveOpinionLabel': 'Save to history',
    'cases.confirm.signOut': 'Sign out and discard unsaved drafts in this tab?',
    'cases.confirm.signOutLabel': 'Sign out',
    'cases.create.analyze': 'Analyze & create case →',
    'cases.create.fileLoaded': '{name} loaded. Click Analyze & create case to continue. Manual fields are ignored.',
    'cases.create.retry': 'Retry original submission',
    'cases.create.saved': 'Case saved',
    'cases.create.savedStatus': 'Case {id} saved. Your later edits were not sent. You can start a new case from this draft.',
    'cases.create.submitting': 'Submitting the original snapshot. Later edits will stay in this form.',
    'cases.create.unconfirmed': 'The original submission is unconfirmed. Retry it to retrieve or finish that case before starting another. Later edits are kept separately.',
    'cases.create.wait': 'Wait for the current case submission to finish before closing the form.',
    'cases.detail.aria': 'Case details',
    'cases.detail.evidence': 'Detection evidence',
    'cases.detail.eyebrow': 'INVESTIGATION DETAILS',
    'cases.detail.fullAnalysis': 'Full analysis & provenance',
    'cases.detail.incomplete': 'Analysis is incomplete; inspect the warnings before deciding.',
    'cases.detail.meta': '{id} · Revision {version} · Created by {actor}',
    'cases.detail.reload': 'Reload case',
    'cases.detail.review': 'Review the evidence before making a decision.',
    'cases.detail.savedText': 'Saved message text',
    'cases.detail.summary': '{label}. {advice}',
    'cases.draft.conflict': 'This draft started at revision {draft}. Compare the latest evidence and history before using it with revision {current}.',
    'cases.draft.discard': 'Discard draft',
    'cases.draft.kept': 'Unsaved draft kept in this tab. Save it before leaving.',
    'cases.draft.rebase': 'I reviewed the latest revision — keep my draft',
    'cases.empty.eyebrow': 'READY WHEN YOU ARE',
    'cases.empty.lead': 'Select a case from the queue to review its evidence, record a decision and follow its history.',
    'cases.empty.note': 'Detection informs. You decide.',
    'cases.empty.title1': 'Every case starts',
    'cases.empty.title2': 'with a closer look.',
    'cases.error.conflict': 'Another analyst changed this case. Your note is still here. Copy it, reload the case, then review the latest version before saving.',
    'cases.error.fileSize': 'Choose a nonempty email or image file up to 2 MiB.',
    'cases.error.input': 'Check the input fields and try again.',
    'cases.error.inputChanged': 'Input changed while reading the file. Submit again.',
    'cases.error.opinionSave': 'Could not confirm the save. Reload the case before retrying.',
    'cases.error.request': 'Request failed. Reload to check whether your last operation completed.',
    'cases.error.visionUnavailable': 'Image recognition is unavailable. Reload the page.',
    'cases.evidence.category': '{label}: {description} Matched: {matched}',
    'cases.evidence.reported': 'Reported signal: {signal}',
    'cases.evidence.warnings': 'Analysis warnings',
    'cases.feedback.caveat': 'This diagnostic snapshot was supplied by the browser; verify before relying on it.',
    'cases.feedback.included': 'included',
    'cases.feedback.notIncluded': 'not included',
    'cases.feedback.report': 'User report: {type} · Original input {input}.',
    'cases.feedback.reporterNote': 'Reporter note: {note}',
    'cases.feedbackTitle': 'User feedback · {type}',
    'cases.filters.active': '{count} active',
    'cases.filters.all': 'All records',
    'cases.filters.allReasons': 'All reasons',
    'cases.filters.allRisks': 'All risks',
    'cases.filters.allStatuses': 'All statuses',
    'cases.filters.allVerdicts': 'All verdicts',
    'cases.filters.apply': 'Apply',
    'cases.filters.aria': 'Case filters',
    'cases.filters.cases': 'Cases',
    'cases.filters.from': 'From (UTC)',
    'cases.filters.fromAria': 'Created from UTC',
    'cases.filters.risk': 'Risk',
    'cases.filters.through': 'Through (UTC)',
    'cases.filters.throughAria': 'Created through UTC',
    'cases.filters.title': 'Filters',
    'cases.filters.type': 'Type',
    'cases.filters.verdict': 'Verdict',
    'cases.footer.caveat': 'Detection supports analyst judgment. A low-risk result is not a guarantee of safety.',
    'cases.history.action.auxiliary_saved': 'Jev opinion saved',
    'cases.history.action.created': 'created',
    'cases.history.action.reopened': 'reopened',
    'cases.history.action.reviewed': 'reviewed',
    'cases.history.change': '{field}: {from} → {to}',
    'cases.history.entry': '{actor} · {action}',
    'cases.history.opinion': '{model} · Requested {time}. Saved model opinion; risk and human verdict unchanged.',
    'cases.history.opinionIncomplete': 'Original evidence was incomplete.',
    'cases.history.provenance': 'Opinion provenance',
    'cases.history.title': 'Activity history',
    'cases.historyCapacity.entries': '{used}/{limit} history entries · {remaining} ordinary history slots remaining.',
    'cases.historyCapacity.full': 'History or storage is full. This case cannot be reopened; create a follow-up investigation.',
    'cases.historyCapacity.legacy': 'Legacy recovery is limited to {limit} KB.',
    'cases.historyCapacity.ok': 'History slots and bytes are reserved for the final workflow steps; saving checks the note size.',
    'cases.historyCapacity.reserved': 'Capacity is reserved for starting work or closing. Choose an available status.',
    'cases.historyCapacity.storage': 'Storage: {used} / {limit} KB · {available} KB available after closure reserves.',
    'cases.jev.attempts': 'Workspace attempts today: {used}/{limit}.',
    'cases.jev.caseChanged': 'The case changed. Reload it before requesting another opinion.',
    'cases.jev.consent': 'I am authorized to send this message to TypeSafe for analysis.',
    'cases.jev.disclosure': 'What is sent to TypeSafe and how results are kept',
    'cases.jev.disclosureText': 'Optional text analysis by TypeSafe. This sends the saved subject, readable message text and any extracted OCR text to TypeSafe. Mailbox names and URL queries are masked, but other personal information may remain. Images, attachments and analyst notes are not sent. The opinion does not change the case risk or verdict. Your structured results are cached for 24 hours. View existing result reads that cache without contacting TypeSafe. Save opinion to history explicitly retains a result for all workspace analysts under the case retention policy. Message text is not copied into opinion records.',
    'cases.jev.failed': 'Auxiliary analysis failed. The original detection result is unchanged.',
    'cases.jev.needConsent': 'Confirm permission to send this message first.',
    'cases.jev.probability': '{label}: {percent}% estimated probability. This is not a severity score.',
    'cases.jev.read': 'View existing result',
    'cases.jev.reading': 'Reading your existing result…',
    'cases.jev.reason.call_budget_exhausted': 'The auxiliary request allowance has been reached.',
    'cases.jev.reason.daily_quota_exhausted': 'The workspace daily allowance is exhausted. Wait for the UTC reset.',
    'cases.jev.reason.empty_or_oversized_text': 'Saved text is empty or exceeds the 12,000-character auxiliary limit.',
    'cases.jev.reason.legacy_source_format': 'This older case lacks separate readable email text. Create a new case from the original email.',
    'cases.jev.reason.local_capacity_exhausted': 'Auxiliary analysis is busy. This attempt did not reach TypeSafe. Wait for current requests to finish.',
    'cases.jev.reason.no_cached_opinion': 'No unexpired result exists for your account and this case. No new model call was made.',
    'cases.jev.reason.provider_access_denied': 'TypeSafe denied access. Ask the administrator to check account and model access.',
    'cases.jev.reason.provider_authentication': 'TypeSafe rejected the API key. Ask the administrator to check the deployment key.',
    'cases.jev.reason.provider_http_error': 'TypeSafe returned a service error. Contact the administrator.',
    'cases.jev.reason.provider_invalid_response': 'TypeSafe returned an unexpected response. Contact the administrator.',
    'cases.jev.reason.provider_network_error': 'The server could not connect to TypeSafe.',
    'cases.jev.reason.provider_overloaded': 'TypeSafe is temporarily overloaded.',
    'cases.jev.reason.provider_rate_limited': 'TypeSafe rate limit reached. Wait before making another request.',
    'cases.jev.reason.provider_request_invalid': 'TypeSafe rejected the request format. Contact the administrator.',
    'cases.jev.reason.provider_timeout': 'TypeSafe timed out. No automatic retry was made.',
    'cases.jev.reason.provider_tls_error': 'The secure connection to TypeSafe could not be verified. Contact the administrator.',
    'cases.jev.reason.request_pending': 'An identical request is still running or its outcome is unknown. No additional provider call was made.',
    'cases.jev.reason.unknown': 'Auxiliary analysis was unavailable or skipped.',
    'cases.jev.receipt': 'This request record is reused until {time}; submitting again will not start another provider call during that period.',
    'cases.jev.reopenToSave': 'Reopen the case before saving this opinion.',
    'cases.jev.requesting': 'Requesting auxiliary opinion…',
    'cases.jev.resets': 'Resets {time}.',
    'cases.jev.result': '{model} · Model opinions, not verified findings. Risk and verdict are unchanged.',
    'cases.jev.resultIncomplete': 'Original evidence is incomplete; this opinion cannot fill missing images or correct OCR.',
    'cases.jev.reused': 'Reused the previous request; no new provider call.',
    'cases.jev.run': 'Request auxiliary opinion',
    'cases.jev.save': 'Save opinion to history',
    'cases.jev.signal.authority_pressure': 'Pressure to bypass normal checks',
    'cases.jev.signal.credential_request': 'Request for authentication secrets',
    'cases.jev.signal.insufficient_evidence': 'Insufficient evidence',
    'cases.jev.signal.payment_redirection': 'New or changed payment destination',
    'cases.jev.signal.phishing_intent': 'Deceptive intent',
    'cases.jev.status.available': 'Jev is configured. Each new request requires your permission. Provider access is checked only when requested.',
    'cases.jev.status.configuration_error': 'Jev configuration is incomplete or invalid. Check this deployment’s API key and daily limit, then redeploy.',
    'cases.jev.status.control_unavailable': 'Jev request controls are unavailable. No new request can be sent. Refresh to check again.',
    'cases.jev.status.disabled': 'Jev is disabled for this deployment. An administrator can enable it and redeploy.',
    'cases.jev.status.quota_exhausted': 'The workspace daily allowance is exhausted. An existing opinion can still be retrieved; new requests resume after the UTC reset.',
    'cases.jev.status.unknown': 'Jev status is unavailable. Refresh to check again.',
    'cases.jev.title': 'Jev auxiliary opinion · Experimental',
    'cases.jev.unchanged': 'The original detection result is unchanged.',
    'cases.kind.case': 'Case',
    'cases.kind.feedback': 'User feedback',
    'cases.login.eyebrow': 'WELCOME TO PHISHGUARD',
    'cases.login.headline1': 'Turn signals',
    'cases.login.headline2': 'into decisions.',
    'cases.login.intro': 'One shared place to investigate suspicious emails, review the evidence and move cases forward.',
    'cases.login.lead': 'Enter your individual access token to open the shared team workspace.',
    'cases.login.section': '01 / ANALYST WORKSPACE',
    'cases.login.step1': 'Collect evidence',
    'cases.login.step2': 'Record a verdict',
    'cases.login.step3': 'Keep the history',
    'cases.login.submit': 'Open workspace',
    'cases.login.title': 'Analyst sign in',
    'cases.login.tokenHelp': 'Use the credential configured for this exact Production or Preview deployment. Refreshing clears it from the tab, but a code release does not revoke it unless its Vercel hash is replaced.',
    'cases.login.tokenLabel': 'Access token',
    'cases.login.tokenPlaceholder': 'Enter your access token',
    'cases.login.workflow': 'Case workflow',
    'cases.meta.description': 'Private PhishGuard workspace where authorized analysts review reported emails, record verdicts and keep an audit trail.',
    'cases.meta.title': 'Cases · PhishGuard',
    'cases.nav.analyzer': 'Email analyzer',
    'cases.nav.aria': 'Workspace navigation',
    'cases.nav.main': 'Main navigation',
    'cases.nav.operations': 'OPERATIONS',
    'cases.nav.workspace': 'Case workspace',
    'cases.notice.caseSaved': 'Case saved.',
    'cases.notice.draftReady': 'Draft ready for a new case. Review the input before submitting.',
    'cases.notice.opinionAlreadySaved': 'This opinion was already saved. The latest case revision is displayed; review any draft conflict before saving.',
    'cases.notice.opinionSaved': 'Jev opinion saved to case history. Human assessment is unchanged.',
    'cases.notice.reviewSaved': 'Review saved.',
    'cases.notice.reviewSavedDraft': 'Review saved. Your newer edits are still unsaved.',
    'cases.overview.closed': 'Closed reports',
    'cases.overview.disabled': 'Feedback storage is not configured.',
    'cases.overview.falseAlerts': 'Confirmed false alerts',
    'cases.overview.missedThreats': 'Confirmed missed threats',
    'cases.overview.open': 'Open reports',
    'cases.overview.status': '{total} retained reports across all dates; queue filters do not affect these counts. Confirmed findings require a closed human review and supporting evidence. These are report counts, not overall model error rates; duplicate reports may be included.',
    'cases.overview.title': 'Feedback overview',
    'cases.overview.unavailable': 'Feedback overview unavailable. Refresh to retry; counts are unknown.',
    'cases.page.current': 'Page {page}',
    'cases.page.next': 'Next',
    'cases.page.nextAria': 'Next page',
    'cases.page.previous': 'Previous',
    'cases.page.previousAria': 'Previous page',
    'cases.queue.aria': 'Cases',
    'cases.queue.casesUnavailable': 'Cases unavailable.',
    'cases.queue.count': '{count} matching records',
    'cases.queue.countPartial': '{count} records from available sources',
    'cases.queue.created': 'Created',
    'cases.queue.empty': 'No cases match these filters.',
    'cases.queue.emptyPartial': 'No matching records from the available sources. Refresh to retry unavailable sources.',
    'cases.queue.feedbackUnavailable': 'User feedback unavailable.',
    'cases.queue.investigation': 'Investigation',
    'cases.queue.partialNote': 'Showing available records only. Refresh to retry.',
    'cases.queue.refresh': 'Refresh',
    'cases.queue.title': 'Case queue',
    'cases.queue.unstable': 'The queue changed again while loading. Refresh to show the remaining records.',
    'cases.reason.evidence_error': 'Evidence issue',
    'cases.reason.false_alert': 'False alert',
    'cases.reason.insufficient_evidence': 'Insufficient evidence',
    'cases.reason.missed_threat': 'Missed threat',
    'cases.reason.no_issue_found': 'No issue found',
    'cases.reason.other': 'Other',
    'cases.reason.risk_level': 'Risk level issue',
    'cases.reportType.false_negative': 'false negative',
    'cases.reportType.false_positive': 'false positive',
    'cases.reportType.incorrect_evidence': 'incorrect evidence',
    'cases.reportType.incorrect_risk': 'incorrect risk',
    'cases.reportType.other': 'other',
    'cases.review.basisLabel': 'Evidence basis',
    'cases.review.capacityReserved': 'History capacity is reserved for closing this case. Choose an available status.',
    'cases.review.compareFirst': 'Compare the latest case history, then confirm your draft against the current revision.',
    'cases.review.feedbackHelp': 'For user feedback, record what you found and the evidence you checked. Reporter-only evidence supports an uncertain verdict. To close: False alert requires Legitimate; Missed threat requires Phishing; Insufficient evidence requires Uncertain.',
    'cases.review.lead': 'Start work before closing a case. Closing requires a human verdict; explain verdict changes in your note. Reopen a closed case to make further changes.',
    'cases.review.noteLabel': 'Review note',
    'cases.review.notePlaceholder': 'Document your reasoning and next steps…',
    'cases.review.optionCapacity': '{status} (history capacity)',
    'cases.review.optionUnavailable': '{status} (no longer available)',
    'cases.review.reasonLabel': 'Review reason',
    'cases.review.save': 'Save review',
    'cases.review.savedTo': 'Saved to the case history',
    'cases.review.selectBasis': 'Select evidence',
    'cases.review.selectReason': 'Select a reason',
    'cases.review.statusGone': 'The saved case no longer supports this status. Choose an available status; your edits are still here.',
    'cases.review.statusLabel': 'Status',
    'cases.review.title': 'Your assessment',
    'cases.review.verdictLabel': 'Human verdict',
    'cases.risk.critical': 'CRITICAL',
    'cases.risk.high': 'HIGH',
    'cases.risk.low': 'LOW',
    'cases.risk.medium': 'MEDIUM',
    'cases.risk.safe': 'SAFE',
    'cases.risk.unknown': 'UNKNOWN',
    'cases.session.label': 'SIGNED IN AS',
    'cases.session.signOut': 'Sign out',
    'cases.sidebar.shared': 'Shared investigations',
    'cases.sidebar.team': 'Team workspace',
    'cases.skip': 'Skip to workspace',
    'cases.source.notIncluded': 'Original input was not included. Review is limited to the diagnostic summary and reporter note.',
    'cases.source.plain': 'Message text is displayed without rendering HTML or loading external content.',
    'cases.source.preview': 'Decoded text preview. Recoverable plain/HTML alternatives and attached message text are shown together. Attachments and remote content are not displayed. Original email bytes are unchanged.',
    'cases.source.previewUnavailable': 'Decoded preview unavailable. Original email remains in saved evidence.',
    'cases.source.truncated': 'Saved text was truncated. See analysis warnings for other coverage limitations.',
    'cases.source.warnings': 'Warnings: {warnings}',
    'cases.status.closed': 'Closed',
    'cases.status.in_progress': 'In progress',
    'cases.status.pending': 'Pending',
    'cases.theme.auto': 'System',
    'cases.theme.dark': 'Dark',
    'cases.theme.label': 'Theme',
    'cases.theme.light': 'Light',
    'cases.topbar.cases': 'Cases',
    'cases.topbar.private': 'Private workspace',
    'cases.verdict.legitimate': 'Legitimate',
    'cases.verdict.none': 'Not reviewed',
    'cases.verdict.phishing': 'Phishing',
    'cases.verdict.uncertain': 'Uncertain',
    'cases.workspace.eyebrow': 'CASE OPERATIONS',
    'cases.workspace.lead': 'Investigate reported messages, record decisions, and preserve the audit trail.',
    'cases.workspace.newCase': 'New case',
    'cases.workspace.title': 'Cases',
  };

  // Other languages' strings are separate files, fetched only for a visitor
  // who uses that language. lang-init.js requests the same URL in <head> for a
  // Chinese page; the asset-version check keeps both ?v= in step.
  const SOURCES = {zh: '/static/i18n-zh.js?v=40'};
  const DICTIONARY = {en};
  const warned = new Set();
  // Callbacks waiting for a language's file, by language code.
  const waiting = {};

  const isDictionary = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  const available = code => Object.hasOwn(DICTIONARY, code);
  const lookup = (code, key) => (available(code) && Object.hasOwn(DICTIONARY[code], key) ? DICTIONARY[code][key] : undefined);

  // A dictionary file that ran before this script left its strings behind.
  try {
    const early = window.PhishGuardI18nDictionaries;
    for (const code of Object.keys(SOURCES)) if (early && isDictionary(early[code])) DICTIONARY[code] = early[code];
    delete window.PhishGuardI18nDictionaries;
  } catch (_error) { /* nothing was left */ }

  function settle(code, ok) {
    const callbacks = waiting[code] || [];
    delete waiting[code];
    callbacks.forEach(callback => callback(ok));
  }

  // Called by a dictionary file (i18n-zh.js) that runs after this script.
  function register(code, dictionary) {
    if (!Object.hasOwn(SOURCES, code) || !isDictionary(dictionary)) return;
    DICTIONARY[code] = dictionary;
    settle(code, true);
  }

  // Calls done(true) once `code`'s dictionary is registered, or done(false)
  // if its file fails to load. The request lang-init.js already started is
  // reused; a failed request is removed, so a later switch asks again.
  function loadDictionary(code, done) {
    if (available(code)) { done(true); return; }
    const started = Object.hasOwn(waiting, code);
    (waiting[code] = waiting[code] || []).push(done);
    if (started) return;
    let script = null;
    const fail = () => {
      if (script && typeof script.remove === 'function') script.remove();
      settle(code, false);
    };
    try {
      script = typeof document.querySelector === 'function'
        ? document.querySelector(`script[data-i18n-dictionary="${code}"]`) : null;
      // lang-init.js marks its request once it finished; finished without
      // registering means it failed.
      if (script && script.getAttribute('data-state')) { fail(); return; }
      if (!script) {
        script = document.createElement('script');
        script.src = SOURCES[code];
        script.setAttribute('data-i18n-dictionary', code);
        (document.head || document.documentElement).appendChild(script);
      }
      script.addEventListener('load', () => (available(code) ? settle(code, true) : fail()));
      script.addEventListener('error', fail);
    } catch (_error) {
      fail();
    }
  }

  function format(template, params) {
    if (!params) return template;
    return template.replace(/\{(\w+)\}/g, (match, name) => (Object.hasOwn(params, name) ? String(params[name]) : match));
  }

  function storedLanguage() {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return value === 'en' || value === 'zh' ? value : null;
    } catch (_error) { return null; }
  }

  // Mirrors lang-init.js: a stored choice wins; otherwise the browser's first
  // preferred language decides, and only zh* selects Chinese.
  function detect() {
    const stored = storedLanguage();
    if (stored) return stored;
    try {
      const preferred = (navigator.languages && navigator.languages[0]) || navigator.language || '';
      return /^zh\b/i.test(String(preferred)) ? 'zh' : 'en';
    } catch (_error) { return 'en'; }
  }

  // The language whose strings are applied: the detected one once its
  // dictionary is here, English until then. `requested` is the language last
  // asked for; a file that arrives after the visitor chose again is not applied.
  let requested = detect();
  let current = available(requested) ? requested : 'en';
  let busy = false;

  function t(key, params) {
    let template = lookup(current, key);
    if (template === undefined) template = lookup('en', key);
    if (template === undefined) {
      if (!warned.has(key)) {
        warned.add(key);
        if (typeof console !== 'undefined') console.warn(`PhishGuardI18n: missing translation key "${key}"`);
      }
      return key;
    }
    return format(template, params);
  }

  // "1 signal" / "2 signals": key.one when count is 1, otherwise key.other.
  const plural = (key, count, params) => t(`${key}.${count === 1 ? 'one' : 'other'}`, {count, ...params});
  const has = key => lookup('en', key) !== undefined;
  const lang = () => current;
  const languageTag = () => HTML_LANG[current];
  const locale = () => LOCALE[current];
  // English keeps the browser's default date format, as before translation.
  const dateLocale = () => (current === 'en' ? undefined : LOCALE[current]);

  // Localizes English text the server identified with a stable code, but only
  // while that text still matches the dictionary; other wording is shown as-is.
  function known(key, serverText) {
    if (current === 'en' || typeof serverText !== 'string' || lookup('en', key) !== serverText) return serverText;
    return lookup(current, key) ?? serverText;
  }

  // A result's risk label (content risk_label, or a sender verdict label kept
  // in a feedback report) is shown as sent in English. Other languages use the
  // exact translation of a known label, else a label for the risk level code,
  // else the label as sent.
  const RISK_LABEL_KEYS = ['critical', 'high', 'highModel', 'medium', 'mediumModel', 'low', 'lowVerified', 'lowRequested', 'safe', 'remoteUnchecked',
    'incomplete', 'imageIncomplete'].map(name => `content.riskLabel.${name}`)
    .concat(['critical', 'high', 'medium', 'low'].map(level => `sender.verdict.${level}`));
  function riskLabel(label, level) {
    if (current === 'en') return label;
    for (const key of RISK_LABEL_KEYS) {
      const localized = known(key, label);
      if (localized !== label) return localized;
    }
    return has(`content.level.${level}`) ? t(`content.level.${level}`) : label;
  }

  // ── Server messages ──
  // Analysis messages arrive as {code, params, msg[, prefixes]}: `msg` is the
  // server's English text, `server.<code>` the same English template, and each
  // prefix ({code, params}, outermost first) wraps the inner text as {text}.
  // A message is localized only when the English rendering of its code and
  // params reproduces `msg` exactly; unknown codes, changed server wording or
  // truncated params show `msg` as sent. Params are data: the result is plain
  // text that callers escape like any other server text.
  const SERVER_PARAMS = {
    // The randomness factors are listed by code, each with its own template.
    'sender.random_username': (lang, params) => {
      const names = String(params.factor_codes ?? '').split(',').filter(Boolean);
      const parts = names.map(name => serverTemplate(lang, `sender.factor.${name}`,
        {value: params.entropy, percent: params[`${name}_percent`]}));
      if (!names.length || parts.includes(undefined)) return params;
      return {...params, factors: parts.join(lang === 'zh' ? '、' : ', ')};
    },
    'content.category': (lang, params) => ({...params, label: categoryLabel(lang, params)}),
    'content.nested_category': (lang, params) => ({...params, label: categoryLabel(lang, params)}),
  };

  function categoryLabel(lang, params) {
    const key = `category.${params.category}.label`;
    return lookup('en', key) === params.label ? lookup(lang, key) ?? params.label : params.label;
  }

  function serverTemplate(lang, code, params) {
    const template = typeof code === 'string' ? lookup(lang, `server.${code}`) : undefined;
    if (template === undefined) return undefined;
    const safe = params && typeof params === 'object' ? params : {};
    return format(template, Object.hasOwn(SERVER_PARAMS, code) ? SERVER_PARAMS[code](lang, safe) : safe);
  }

  function serverIn(lang, entry) {
    let text = serverTemplate(lang, entry.code, entry.params);
    const prefixes = Array.isArray(entry.prefixes) ? entry.prefixes : [];
    for (let index = prefixes.length - 1; index >= 0 && text !== undefined; index--) {
      const prefix = prefixes[index] || {};
      text = serverTemplate(lang, prefix.code, {...(prefix.params && typeof prefix.params === 'object' ? prefix.params : {}), text});
    }
    return text;
  }

  function server(entry) {
    if (!entry || typeof entry !== 'object') return entry;
    const text = entry.msg;
    if (current === 'en' || typeof text !== 'string' || typeof entry.code !== 'string') return text;
    if (serverIn('en', entry) !== text) return text;
    return serverIn(current, entry) ?? text;
  }

  // Localizes a list of server strings through its parallel *_details entries
  // (matched by text); strings without a detail are shown as sent.
  function serverList(values, details) {
    const byText = new Map();
    for (const detail of Array.isArray(details) ? details : []) {
      if (detail && typeof detail.msg === 'string' && !byText.has(detail.msg)) byText.set(detail.msg, detail);
    }
    return (Array.isArray(values) ? values : []).map(value => (byText.has(value) ? server(byText.get(value)) : value));
  }

  function apply(root) {
    const scope = root || (typeof document !== 'undefined' ? document : null);
    if (!scope || typeof scope.querySelectorAll !== 'function') return;
    scope.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.getAttribute('data-i18n')); });
    // Only dictionary strings (trusted, <kbd> markup) are ever written as HTML.
    scope.querySelectorAll('[data-i18n-html]').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
    scope.querySelectorAll('[data-i18n-attr]').forEach(el => {
      for (const pair of el.getAttribute('data-i18n-attr').split(';')) {
        const [attr, key] = pair.split(':').map(part => part.trim());
        if (attr && key) el.setAttribute(attr, t(key));
      }
    });
  }

  function updateToggle() {
    if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function') return;
    document.querySelectorAll('[data-lang-option]').forEach(option => {
      option.classList.toggle('is-active', option.getAttribute('data-lang-option') === current);
    });
  }

  function applyDocument() {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    if (root) root.lang = HTML_LANG[current];
    apply(document);
    // A page whose <title> carries data-i18n (cases.html) is covered by apply().
    const title = typeof document.querySelector === 'function' ? document.querySelector('title[data-i18n]') : null;
    if (!title) document.title = t('meta.title');
    updateToggle();
  }

  function dispatch(type, detail) {
    if (typeof document !== 'undefined' && typeof document.dispatchEvent === 'function' && typeof CustomEvent === 'function') {
      document.dispatchEvent(new CustomEvent(type, {detail}));
    }
  }

  const langToggle = () => (typeof document !== 'undefined' && typeof document.getElementById === 'function'
    ? document.getElementById('lang-toggle') : null);

  // While another language's file loads the page keeps its current language
  // and the toggle reports itself busy (and ignores clicks).
  function setBusy(value) {
    busy = value;
    const toggle = langToggle();
    if (!toggle) return;
    if (value) toggle.setAttribute('aria-busy', 'true');
    else if (typeof toggle.removeAttribute === 'function') toggle.removeAttribute('aria-busy');
  }

  // Pages announce this (see app.js, cases.js); the console keeps a record.
  function loadFailed(code) {
    if (typeof console !== 'undefined') console.error(`PhishGuardI18n: the ${code} strings could not be loaded; the page stays in English`);
    dispatch('phishguard:languageerror', {lang: code});
  }

  // `announce` tells page scripts to re-render what they wrote.
  function activate(code, announce) {
    current = code;
    applyDocument();
    if (announce) dispatch('phishguard:languagechange', {lang: current});
  }

  // Switches at once when the language's strings are here; otherwise loads
  // them first and returns the unchanged current language.
  function setLang(code) {
    if (code !== 'en' && !Object.hasOwn(SOURCES, code)) return current;
    requested = code;
    if (!available(code)) {
      setBusy(true);
      loadDictionary(code, ok => {
        setBusy(false);
        if (!ok) {
          if (requested === code) requested = current;
          loadFailed(code);
        } else if (requested === code) {
          setLang(code);
        }
      });
      return current;
    }
    try { localStorage.setItem(STORAGE_KEY, code); } catch (_error) { /* choice lasts for this page only */ }
    if (code === current) return current;
    activate(code, true);
    return current;
  }

  // The markup above this script is parsed: translate it before first paint.
  // English needs no pass, since the markup already is the English text.
  // lang-init.js hid a Chinese page (data-i18n-pending) and started loading
  // its strings. If they are already here the page is translated now;
  // otherwise it stays hidden until they arrive (or fail: then it is shown in
  // English), with the stylesheets' 2 s reveal as the backstop.
  if (typeof document !== 'undefined' && document.documentElement) {
    const root = document.documentElement;
    const reveal = () => { if (typeof root.removeAttribute === 'function') root.removeAttribute('data-i18n-pending'); };
    const wanted = requested;
    if (wanted === 'en') {
      root.lang = HTML_LANG.en;
      reveal();
    } else if (available(wanted)) {
      // Reveal the page even if translating it failed.
      try { applyDocument(); } finally { reveal(); }
    } else {
      loadDictionary(wanted, ok => {
        try {
          if (!ok) {
            if (requested === wanted) requested = 'en';
            root.lang = HTML_LANG[current];
            loadFailed(wanted);
          } else if (requested === wanted) {
            // Scripts that already rendered (after DOMContentLoaded) re-render;
            // before it, they have not rendered yet and will use this language.
            activate(wanted, document.readyState !== 'loading');
          }
        } finally { reveal(); }
      });
    }
    const toggle = langToggle();
    if (toggle && typeof toggle.addEventListener === 'function') {
      toggle.addEventListener('click', () => { if (!busy) setLang(current === 'zh' ? 'en' : 'zh'); });
    }
  }

  return {t, plural, has, known, riskLabel, server, serverList, lang, languageTag, locale, dateLocale, setLang, apply, detect,
    register, STORAGE_KEY, DICTIONARY};
})();
