"""Experimental defensive email intent rules, disabled by default.

This draft is developed against synthetic fixtures. Independent holdout
evaluation remains pending. Sender-domain comparison does not authenticate
a sender. Finding codes are provided by the server message registry.
"""
from __future__ import annotations

import contextvars
import re

from content_rules import _unlisted_off_sender_host
from server_messages import indicator

INTENT_RULE_NAMES = ('credential', 'payment')
ENABLED: contextvars.ContextVar[frozenset] = contextvars.ContextVar('intent_rules', default=frozenset())
CODES = {'credential': 'content.intent.credential_handover', 'payment': 'content.intent.payment_redirection'}
POINTS = 3

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'“”‘’（）()]+", re.IGNORECASE)
_CLAUSE_ZH = re.compile(r"[，,；;：:]")

# ── Shared: who is asking ────────────────────────────────────────────────────────
# A request is the reader's to carry out when it heads its clause, after at most a polite or
# sequencing word, or follows "you need to", "we need you to", or "by" for a gerund.
_HEAD_EN = re.compile(
    r"(?:(?:^|[,:;—–(\[>]|\b(?:and|then|so|or|now|also)\b)\s*(?:(?:please|kindly|simply|just|now|then|also|first|quickly"
    r"|immediately|urgently|today)\s+)*"
    r"|\b(?:you\s+(?:must|need\s+to|should|have\s+to|will\s+need\s+to|are\s+required\s+to|are\s+asked\s+to|can|may)"
    r"|we\s+need\s+you\s+to|we\s+require\s+you\s+to|make\s+sure\s+(?:you|to)|be\s+sure\s+to|remember\s+to"
    r"|don['’]t\s+forget\s+to)\s+(?:(?:simply|just|also|now|please)\s+)*)$", re.IGNORECASE)
_BY_EN = re.compile(r"\bby\s+$", re.IGNORECASE)
# Attribution markers are applied to individual unquoted clauses below.
_ATTRIBUTED_EN = re.compile(
    r"\b(?:scammers?|fraudsters?|criminals?|attackers?|hackers?|impostors?|imposters?|crooks?|thieves|con\s+artists?"
    r"|if\s+(?:you\s+(?:ever\s+)?(?:receive|get|see)|someone|anyone|somebody|a\s+caller|they)|anyone\s+who|someone\s+who"
    r"|asks?\s+you\s+to|asked\s+(?:you\s+)?to|asking\s+(?:you\s+)?to|requests?\s+(?:that\s+)?you\s+to"
    r"|claim(?:s|ing)?\s+to\s+be|pretend(?:s|ing)?\s+to\s+be|posing\s+as|(?:e-?mails?|messages?|texts?|calls?)\s+(?:saying|that\s+says?)"
    r"|never\s+(?:ask|request|call|e-?mail|text)|will\s+not\s+(?:ask|request)|won['’]t\s+(?:ask|request)"
    r"|do(?:es)?\s+not\s+(?:ask|request)|don['’]t\s+(?:ask|request))\b", re.IGNORECASE)
_ATTRIBUTED_ZH = re.compile(r"骗子|诈骗|不法分子|犯罪分子|冒充|假冒|钓鱼|如收到|如果收到|若收到|如遇|如有人|若有人|如果有人"
                            r"|任何人(?:要求|索要|让)|谨防|警惕|常说|声称|自称|绝不会|不会(?:要求|索要|通过)|从不(?:要求|索要)")
_REQUEST_HEAD_ZH = re.compile(r"请|只需|只要|务必|麻烦|烦请|需要|需|即可|立即|马上|尽快|直接")
_NEGATION_ZH = re.compile(r"请勿|勿|不要|切勿|不会|绝不|不得|千万别|不能|无需|无须|不必|严禁|别|从不|暂不")

# ── Credential handover ──────────────────────────────────────────────────────────
_TRANSFER_EN = (r"reply(?:ing)?|respond(?:ing)?|send(?:ing)?|provid(?:e|ing)|giv(?:e|ing)|tell(?:ing)?|shar(?:e|ing)"
                r"|submit(?:ting)?|forward(?:ing)?|suppl(?:y|ying)|disclos(?:e|ing)|includ(?:e|ing)|let(?:ting)?\s+us\s+know"
                r"|writ(?:e|ing)\s+back|read(?:ing)?(?=\s+(?:out|aloud|back|him|her|them|us|me|to)\b)"
                r"|(?:e-?mail|text)(?:ing)?(?=\s+(?:us|me|it|them|back)\b)")
_ENTRY_EN = (r"enter(?:ing)?|re-?enter(?:ing)?|typ(?:e|ing)|re-?typ(?:e|ing)|input(?:ting)?|key(?:ing)?\s+in|fill(?:ing)?\s+in"
             r"|confirm(?:ing)?|verify(?:ing)?|validat(?:e|ing)")
_ACT_EN = re.compile(rf"\b(?:(?P<transfer>{_TRANSFER_EN})|(?P<entry>{_ENTRY_EN}))\b", re.IGNORECASE)
_CODE_KIND = (r"(?:(?:\d|three|four|five|six|seven|eight|nine|ten)[\s-]?digit|verification|security|confirmation|authentication"
              r"|authori[sz]ation|sign[\s-]?in|log[\s-]?in|login|access|sms|text|otp|2fa|mfa|two[\s-]?factor|one[\s-]?time)")
_SECRET_EN = re.compile(
    r"\b(?:pass(?:word|code|phrase)s?|pass\s+phrases?|(?-i:PINs?)|pin\s+(?:codes?|numbers?)|(?:login|log-in|sign[\s-]?in)\s+"
    r"(?:details|credentials)|credentials"
    rf"|{_CODE_KIND}(?:\s+{_CODE_KIND})?\s+(?:pass)?codes?|one[\s-]?time\s+pass(?:code|word)s?|otps?"
    r"|(?:backup|recovery)\s+(?:codes?|keys?|phrases?)|(?:seed|secret|recovery|mnemonic)\s+(?:phrases?|words?)|private\s+keys?"
    # Paraphrases: "the phrase you use when you sign in", "the word you type to unlock your account".
    r"|(?:the|that|this)\s+(?:phrase|word|words|code|number|characters|combination|secret)\s+(?:that\s+|which\s+)?you\s+"
    r"(?:normally\s+|usually\s+|always\s+)?(?:use|type|enter|need)\b[^.;!?]{0,30}?\b(?:(?:sign|log)(?:ging)?[\s-]?(?:in|on)"
    r"|unlock|access|bank(?:ing)?)"
    # "the code that appears on your screen", "the code we just texted you".
    r"|(?:the|that|this)\s+code\s+(?:that\s+|which\s+)?(?:we\s+|you\s+)?(?:just\s+)?(?:sent|texted|e-?mailed|received?|get|got"
    r"|appears?|appeared|shows?|showed|will\s+(?:receive|get)))\b", re.IGNORECASE)
# Where an act's object ends: a new clause.
_SPAN_END_EN = re.compile(r"[.;!?]|\b(?:so\s+(?:that|we|our|you|it|they)|if|when|because|unless|after|before|once|while"
                          r"|in\s+order)\b", re.IGNORECASE)
# A secret that is not the reader's to hand over: a new one being chosen, one excluded, a code the
# message itself gives, or a word about the secret rather than the secret.
_NOT_HANDED_BEFORE_EN = re.compile(r"\b(?:new|reset|change|changing|forgot(?:ten)?|choose|create|set|not|never|no|without"
                                   r"|except)\s+(?:\w+\s+){0,2}$", re.IGNORECASE)
_NOT_HANDED_AFTER_EN = re.compile(r"^\s*(?:(?:is|was|[:：#-])\s*)?\d{4,8}\b|^\s+(?:reset|change|update|policy|policies|manager"
                                  r"|requirements?|strength|expir\w*|hint|protected|link)\b", re.IGNORECASE)
_PRONOUN_OBJECT_EN = re.compile(r"^\s*(?:(?:us|me|back)\s+)*(?:it|them|these|those|this|that)\b", re.IGNORECASE)
_TO_READER_EN = re.compile(r"^\s+(?:you|yourself)\b", re.IGNORECASE)
_REPLY_EN = re.compile(r"\b(?:repl(?:y|ying)|respond(?:ing)?|write\s+back)\b|\bthis\s+(?:e-?mail|message|address)\b",
                       re.IGNORECASE)

_TRANSFER_ZH = r"回复|发送|发给|发到|传给|提供|告知|告诉|报给|转发|说出|念给|读给|透露|交给|提交|报出"
_ENTRY_ZH = r"输入|填写|填入|录入|键入|确认|验证|核对"
_SECRET_ZH = (r"(?:支付|取款|登录|网银|邮箱|账户|帐户|账号|银行卡|交易|当前|原|动态)?(?:密码|口令)"
              r"|(?:短信|手机|动态|[四六4-8]位)?(?:验证码|校验码|动态码|安全码)|助记词|私钥|恢复码|备用码|备份码")
_STOP_ZH = r"[^，。！？；,;!?：:]"
_DIRECT_ZH = re.compile(rf"(?P<act>{_TRANSFER_ZH}|{_ENTRY_ZH})(?P<mid>{_STOP_ZH}{{0,15}}?)(?P<secret>{_SECRET_ZH})")
_BA_ZH = re.compile(rf"(?:把|将)(?P<mid>{_STOP_ZH}{{0,25}}?)(?P<secret>{_SECRET_ZH})(?P<mid2>{_STOP_ZH}{{0,10}}?)"
                    rf"(?P<act>{_TRANSFER_ZH}|{_ENTRY_ZH})")
_BA_PRONOUN_ZH = re.compile(rf"(?:把|将)(?:其|它们?|这些|该码|此码){_STOP_ZH}{{0,6}}?(?P<act>{_TRANSFER_ZH}|{_ENTRY_ZH})")
_SECRET_ZH_ANY = re.compile(_SECRET_ZH)
_NOT_HANDED_BEFORE_ZH = re.compile(r"(?:新|重置|修改|设置|找回|更改)的?$")
_NOT_HANDED_AFTER_ZH = re.compile(r"^\s*(?:是|为|[:：])?\s*\d{4,8}")
_TO_READER_ZH = re.compile(r"^给?(?:您|你)(?!的)")
_ENTRY_ZH_ONLY = re.compile(_ENTRY_ZH)


_CONNECTOR_RE = re.compile(r"^(?:(?:but|and)\s+|(?:但是|并且|但)\s*)", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'“”‘’（）()\[\]，。！？；]+", re.IGNORECASE)
_SENT_SPLIT_RE = re.compile(r"[.!?。！？;；\n]+")
_INSTRUCT_RE = re.compile(
    r"follow the quoted request below|follow the instructions below|do this as instructed below"
    r"|请照做下方要求|请按照下方说明完成|请遵循下方说明"
    r"|\bplease\s+(?:do|action|process|complete|follow)\b"
    r"|请(?:今天|现在|立即|马上)?(?:处理|完成|照做|照办|执行|按(?:照)?[^，。！？；]{0,15}(?:要求|请求|说明|操作))",
    re.IGNORECASE)
_NEGATED_FOLLOW_RE = re.compile(
    r"\b(?:do\s+not|don['’]t|never|no\s+need\s+to)\s+(?:do|action|process|complete|follow|carry\s+out)\b"
    r"|(?:请)?(?:勿|不要|别|切勿)(?:照做|照办|处理|完成|执行|遵循|按照)", re.IGNORECASE)


def _protect_urls(text):
    prefix = '__IRURL_'
    while prefix in text:
        prefix += 'X'
    mapping = {}
    def callback(match):
        raw = match.group(0)
        url = raw.rstrip('.,;!?')
        suffix = raw[len(url):]
        token = f'{prefix}{len(mapping)}__'
        mapping[token] = url
        return token + suffix
    return (_URL_RE.sub(callback, text), mapping)


def _restore_urls(text, mapping):
    for token, url in mapping.items():
        text = text.replace(token, url)
    return text


def _sentences(text):
    protected, mapping = _protect_urls(text)
    parts = _SENT_SPLIT_RE.split(protected)
    return [_restore_urls(p, mapping) for p in parts if p.strip()]


def _request_units(text):
    protected, mapping = _protect_urls(text)
    units = []
    buffer = []
    quote_close = None
    quote_reported = True
    pending_instruction = False
    last_reported = False
    adoption_sentence = None
    forwarded_reported = None
    sentence_index = 0

    def flush(quoted):
        nonlocal pending_instruction, last_reported, adoption_sentence
        raw = _restore_urls(''.join(buffer), mapping).strip()
        buffer.clear()
        if not raw:
            return
        if quoted:
            reported = quote_reported
        else:
            raw = _CONNECTOR_RE.sub('', raw)
            reported = bool(_ATTRIBUTED_EN.search(raw) or _ATTRIBUTED_ZH.search(raw)
                            or forwarded_reported is True)
            pending_instruction = bool(not reported and _INSTRUCT_RE.search(raw)
                                       and not _NEGATED_FOLLOW_RE.search(raw))
            if pending_instruction:
                adoption_sentence = sentence_index
            elif reported or _NEGATED_FOLLOW_RE.search(raw):
                adoption_sentence = None
        last_reported = reported
        units.append((raw, sentence_index, reported))

    pos = 0
    while pos < len(protected):
        ch = protected[pos]
        if quote_close is not None:
            if ch == quote_close:
                flush(True)
                if ch == '\n':
                    sentence_index += 1
                quote_close = None
            elif ch in '.!?。！？;；':
                flush(True)
                sentence_index += 1
            else:
                buffer.append(ch)
            pos += 1
            continue

        marker = _INLINE_FORWARD_RE.match(protected, pos)
        if marker:
            flush(False)
            fresh_adoption = adoption_sentence is not None and 0 <= sentence_index - adoption_sentence <= 1
            forwarded_reported = bool(last_reported or not (pending_instruction or fresh_adoption))
            pos = marker.end()
            continue

        if buffer and pos and protected[pos - 1].isspace() and _CAP_REQUEST_RE.match(protected, pos):
            prefix = _restore_urls(''.join(buffer), mapping)
            if not (_ATTRIBUTED_EN.search(prefix) or _ATTRIBUTED_ZH.search(prefix)
                    or _TAIL_NEGATION_RE.search(prefix) or _POLITE_PREFIX_ONLY_RE.fullmatch(prefix)):
                flush(False)

        apostrophe = (ch == "'" and pos and pos + 1 < len(protected)
                      and protected[pos - 1].isalnum() and protected[pos + 1].isalnum())
        if ch in ('"', "'", '“', '‘') and not apostrophe:
            flush(False)
            fresh_adoption = adoption_sentence is not None and 0 <= sentence_index - adoption_sentence <= 1
            quote_reported = bool(last_reported or forwarded_reported is True
                                  or (forwarded_reported is None and not (pending_instruction or fresh_adoption)))
            quote_close = {'"': '"', "'": "'", '“': '”', '‘': '’'}[ch]
        elif ch == '>' and (not pos or protected[pos - 1].isspace()):
            flush(False)
            fresh_adoption = adoption_sentence is not None and 0 <= sentence_index - adoption_sentence <= 1
            quote_reported = bool(last_reported or forwarded_reported is True
                                  or (forwarded_reported is None and not (pending_instruction or fresh_adoption)))
            quote_close = '\n'
        elif ch in ',，':
            flush(False)
        elif ch in '.!?。！？;；\n':
            flush(False)
            sentence_index += 1
        else:
            buffer.append(ch)
        pos += 1
    flush(quote_close is not None)
    return units


def _secret_en(span: str, limit: int) -> bool:
    for match in _SECRET_EN.finditer(span):
        if match.start() >= limit:
            break
        if not (_NOT_HANDED_BEFORE_EN.search(span[max(0, match.start() - 30):match.start()])
                or _NOT_HANDED_AFTER_EN.search(span[match.end():])):
            return True
    return False


def _secret_zh(text: str) -> bool:
    return any(not (_NOT_HANDED_BEFORE_ZH.search(text[:match.start()]) or _NOT_HANDED_AFTER_ZH.search(text[match.end():]))
               for match in _SECRET_ZH_ANY.finditer(text))


def _handover_en(sentences: list[str], index: int) -> str | None:
    """'transfer' or 'entry' where the sentence asks the reader to hand over a secret in English."""
    sentence = sentences[index]
    for match in _ACT_EN.finditer(sentence):
        act = match.group(0).lower()
        head = sentence[:match.start()]
        if not (_BY_EN.search(head) if act.endswith('ing') else _HEAD_EN.search(head)):
            continue
        rest = sentence[match.end():match.end() + 120]
        if match.group('transfer') and _TO_READER_EN.match(rest):
            continue
        end = _SPAN_END_EN.search(rest)
        found = _secret_en(rest, end.start() if end else len(rest))
        if not found and _PRONOUN_OBJECT_EN.match(rest) and index:
            found = _secret_en(sentences[index - 1], len(sentences[index - 1]))
        if found:
            return 'transfer' if match.group('transfer') or _REPLY_EN.search(sentence) else 'entry'
    return None


def _handover_zh(sentences: list[str], index: int) -> str | None:
    """'transfer' or 'entry' where the sentence asks the reader to hand over a secret in Chinese."""
    sentence = sentences[index]
    for clause in _CLAUSE_ZH.split(sentence):
        for pattern in (_DIRECT_ZH, _BA_ZH, _BA_PRONOUN_ZH):
            for match in pattern.finditer(clause):
                head = clause[:match.start()]
                if _NEGATION_ZH.search(head) or not (_REQUEST_HEAD_ZH.search(head) or not head.strip()):
                    continue
                if pattern is _DIRECT_ZH:
                    if (_TO_READER_ZH.match(match.group('mid'))
                            and not match.group('mid').rstrip().endswith('的')):
                        continue
                    before, after = clause[:match.start('secret')], clause[match.end('secret'):]
                    if _NOT_HANDED_BEFORE_ZH.search(before) or _NOT_HANDED_AFTER_ZH.search(after):
                        continue
                elif pattern is _BA_ZH:
                    if _TO_READER_ZH.match(clause[match.end():]):
                        continue
                    if (_NOT_HANDED_BEFORE_ZH.search(clause[:match.start('secret')])
                            or _NOT_HANDED_AFTER_ZH.search(clause[match.end('secret'):])):
                        continue
                elif not (index and _secret_zh(sentences[index - 1])):
                    continue
                if _ENTRY_ZH_ONLY.fullmatch(match.group('act')) and '回复' not in sentence:
                    return 'entry'
                return 'transfer'
    return None


def _bound_entry_target(clause, units, sentence_index, links):
    def urls(value):
        return list(dict.fromkeys(match.group(0).rstrip('.!?;:。！？；)]}')
                                 for match in _URL_RE.finditer(value)))

    def named(value):
        normalized = ' '.join(value.split()).casefold()
        return list(dict.fromkeys(destination for label, destination in links or ()
                                  if label and not _REFERENCE_ONLY_RE.search(label)
                                  and label.casefold() not in {'this link', 'click here', 'here', '此链接', '下方链接'}
                                  and ' '.join(label.split()).casefold() in normalized))

    inline = urls(clause)
    if len(inline) == 1:
        return inline[0]
    if len(inline) > 1:
        return None
    labelled = named(clause)
    if len(labelled) == 1:
        return labelled[0]
    if len(labelled) > 1:
        return None
    current = next((index for index, (value, index_sent, reported) in enumerate(units)
                    if value == clause and index_sent == sentence_index and not reported), None)
    if current is not None and current > 0:
        previous, previous_sentence, previous_reported = units[current - 1]
        plain_previous = _URL_RE.sub('', previous)
        if (not previous_reported and 0 <= sentence_index - previous_sentence <= 1
                and _ENTRY_PAGE_CONTEXT_RE.search(plain_previous)
                and not _REFERENCE_ONLY_RE.search(plain_previous)):
            previous_urls = urls(previous) or named(previous)
            if len(previous_urls) == 1:
                return previous_urls[0]
    explicit_local = bool(_LOCAL_PAGE_REFERENCE_RE.search(clause))
    page_names = {' '.join(match.group(0).split()).casefold()
                  for match in _ENTRY_PAGE_CONTEXT_RE.finditer(clause)}
    if not explicit_local and not page_names:
        return None
    if current is not None:
        for value, index_sent, reported in units[current + 1:current + 3]:
            if index_sent - sentence_index > 1:
                break
            if reported:
                break
            without_urls = _URL_RE.sub('', value)
            if _REFERENCE_ONLY_RE.search(without_urls):
                break
            if page_names and not explicit_local:
                local_names = {' '.join(match.group(0).split()).casefold()
                               for match in _ENTRY_PAGE_CONTEXT_RE.finditer(without_urls)}
                if not page_names & local_names:
                    continue
            candidates = urls(value) or named(value)
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                return None
            if _CAP_REQUEST_RE.match(value):
                break
    if explicit_local and len(links or ()) == 1:
        label, destination = links[0]
        if not _REFERENCE_ONLY_RE.search(label or ''):
            return destination
    return None

def credential_handover(text: str, links, sender_domain: str = '', display_name: str = '') -> bool:
    units = _request_units(text)
    previous = None
    rendering_links = list(links or ())
    for clause, sidx, reported in units:
        if reported:
            previous = None
            continue
        prepared = _URL.sub('link', clause)
        kind = _handover_en([prepared], 0) or _handover_zh([prepared], 0)
        if kind is None and prepared.strip().startswith('在') and ('输入' in prepared or '填写' in prepared):
            kind = _handover_zh(['请' + prepared], 0)
        if kind is None and previous is not None and 0 <= sidx - previous[0] <= 1:
            prev_clause = previous[1]
            kind = _handover_en([prev_clause, prepared], 1) or _handover_zh([prev_clause, prepared], 1)
        if kind == 'transfer':
            return True
        if kind == 'entry':
            target = _bound_entry_target(clause, units, sidx, rendering_links)
            if target and _unlisted_off_sender_host(target, sender_domain):
                return True
        previous = (sidx, prepared)
    return False


# ── Payment redirection ──────────────────────────────────────────────────────────
_NEW_EN = r"(?:new|updated|changed|replacement|alternate|alternative|different|temporary|secondary)"
_MONEY_TARGET_EN = (r"(?:(?:bank(?:ing)?|beneficiary|receiving|payment|remittance|escrow|wire|payee|business|company|corporate)\s+)?"
                    r"(?:bank\s+|beneficiary\s+|receiving\s+|escrow\s+)?(?:accounts?|beneficiar(?:y|ies)|payees?|iban|routing(?:\s+number)?"
                    r"|sort\s+code|banks?|(?:wallet|bitcoin|btc|crypto|usdt)\s+address)\b"
                    r"|(?:bank(?:ing)?|beneficiary|remittance|payment|wire|account)\s+(?:details|information|info|instructions"
                    r"|coordinates)\b|address\s+(?:bc1|0x|[13])\w{10,}")
_NEW_TARGET_EN = re.compile(rf"\b{_NEW_EN}\s+(?:{_MONEY_TARGET_EN})", re.IGNORECASE)
# "a new account", "your new account", "open a new account": the reader's own, not a payee's.
_NOT_A_PAYEE_EN = re.compile(r"\b(?:a|an|your|their|his|her|no|not|never|any|open(?:ing)?|create|creating)\s+$", re.IGNORECASE)
_CHANGED_EN = re.compile(
    r"\b(?:bank(?:ing)?|account|remittance|payment|beneficiary|wire|escrow|payee|receiving)(?:\s+(?:details|account|information"
    r"|info|instructions|coordinates|accounts))?\s+(?:have|has)\s+(?:recently\s+|now\s+|just\s+)?(?:been\s+)?(?:changed|updated"
    r"|moved|switched|replaced)\b"
    r"|\b(?:changed|switched)\s+(?:our\s+)?banks?\b|\bmoved\s+(?:our\s+(?:account|banking)\s+)?to\s+(?:a\s+)?new\s+bank\b"
    r"|\b(?:usual|regular|old|previous|current|existing|original)\s+(?:bank\s+)?account\s+(?:is|has\s+been|was)\s+(?:now\s+)?"
    r"(?:frozen|closed|suspended|blocked|unavailable|under\s+(?:audit|review)|no\s+longer\s+(?:valid|active|in\s+use))"
    r"|\bdetails\s+(?:on\s+file|we\s+have|you\s+have)\s+(?:are|is)\s+no\s+longer\s+(?:valid|in\s+use|active)"
    r"|\b(?:replace|supersede)s?\s+any\s+(?:\w+\s+){0,3}on\s+file\b"
    r"|\b(?:change|update|switch)\s+(?:my|our)\s+(?:direct\s+deposit|payroll|salary|bank(?:ing)?|remittance|payment)\b",
    re.IGNORECASE)
_PAY_EN = re.compile(
    r"\b(?:pay|wire|transfer|remit|settle|deposit|clear"
    r"|send\s+(?:\S+\s+){0,3}?(?:payments?|funds|money|balance|amount|deposit|remittance|transfer|bitcoin|btc|crypto|coins|usdt)"
    r"|make\s+(?:\S+\s+){0,2}?payments?|direct\s+(?:\S+\s+){0,2}?(?:payments?|funds)|route\s+(?:\S+\s+){0,2}?(?:payments?|funds)"
    r"|process\s+(?:\S+\s+){0,2}?(?:payments?|transfer|wire)|use\s+(?:\S+\s+){0,8}?(?:to|for)\s+(?:pay|settle|clear|remit"
    r"|payments?|the\s+payment)|change\s+my\s+direct\s+deposit)\b", re.IGNORECASE)
_PAY_PASSIVE_EN = re.compile(r"\b(?:invoice|payments?|balance|funds|money|amount|deposit|remittance)\s+(?:should|must|needs?\s+to"
                             r"|has\s+to|can)\s+(?:now\s+)?(?:go|be\s+(?:paid|sent|wired|transferred|remitted|made|directed))\b",
                             re.IGNORECASE)
_UNCHANGED_EN = re.compile(r"\b(?:usual|current|existing|same|original|regular)\s+(?:bank\s+)?account|\baccount\s+(?:on\s+file"
                           r"|we\s+have)\b", re.IGNORECASE)
_BYPASS_EN = re.compile(
    r"\b(?:do\s+not|don['’]t|no\s+need\s+to|there\s+is\s+no\s+need\s+to|you\s+don['’]t\s+need\s+to|without)\s+(?:\w+\s+){0,2}?"
    r"(?:call(?:ing)?|phon(?:e|ing)|ring(?:ing)?|contact(?:ing)?|confirm(?:ing)?|verify(?:ing)?|check(?:ing)?)\b"
    r"|\bphone\s+lines?\s+(?:are|is)\s+(?:down|unavailable|out\s+of\s+(?:order|service))|\b(?:cannot|can['’]t)\s+be\s+reached\s+by"
    r"\s+phone|\bconfidential\b|\bkeep\s+(?:this|it)\s+(?:\w+\s+){0,2}?(?:between\s+us|quiet|private|to\s+yourself)"
    r"|\b(?:the\s+change|this\s+change|this|it)\s+is\s+(?:very\s+)?urgent\b"
    r"|\b(?:replace|supersede)s?\s+any\s+(?:\w+\s+){0,3}on\s+file\b"
    r"|\b(?:instead\s+of|rather\s+than|not)\s+the\s+(?:one|account)\s+(?:in|on)\s+(?:our\s+|your\s+)?(?:\w+\s+)?file\b"
    r"|\bdo\s+not\s+use\s+the\s+(?:old|previous|former|usual|original)\s+(?:bank\s+)?(?:account|details)", re.IGNORECASE)
_KNOWN_CHANNEL_EN = re.compile(
    r"\b(?:confirm|verify|check|call|phone|ring|contact)\w*\b[^.;!?]{0,80}?\b(?:number|phone|contact)\b[^.;!?]{0,40}?"
    r"\b(?:you\s+already\s+have|already\s+have|on\s+file|you\s+have\s+for\s+us|in\s+your\s+(?:existing\s+)?(?:contract|records)"
    r"|known|you\s+know|we\s+gave\s+you|printed\s+on)|\bin\s+person\b", re.IGNORECASE)

_MONEY_TARGET_ZH = (r"(?:收款|对公|银行|公司)?(?:账户|帐户|账号|收款单位|收款信息|收款人|开户行|开户银行|钱包地址|钱包)")
_NEW_TARGET_ZH = re.compile(rf"(?:新的?|备用的?|变更后的?|更新后的?){_MONEY_TARGET_ZH}")
_NOT_A_PAYEE_ZH = re.compile(r"(?:您的|你的|开通|开立|注册|创建|开设|没有|无)$")
_CHANGED_ZH = re.compile(
    r"(?:银行账户|收款账户|收款账号|账户|帐户|账号|开户行|开户银行|银行|收款信息|收款方式|收款人|付款信息|汇款信息|收款单位)(?:信息)?"
    r"(?:已经?|现已|已于近日)(?:变更|更改|更换|变动|修改|更新|调整)"
    r"|(?:已经?|现已)(?:变更|更改|更换|改用|启用)了?(?:新的?)?(?:开户银行|开户行|银行|收款账户|收款账号|账户|帐户|账号)"
    r"|更换了(?:开户银行|开户行|银行|收款账户|账户|帐户)|换了(?:开户)?银行"
    r"|原(?:有|来的?)?(?:收款)?(?:账户|帐户|账号|收款信息|银行信息)(?:已经?)?(?:失效|作废|被?冻结|停用|注销|不再使用|无法使用)"
    r"|(?:账户|帐户)(?:已经?)?被冻结")
_PAY_ZH = re.compile(r"汇入|汇至|汇到|汇往|转入|转到|转至|转账至|转账到|支付到|支付至|付至|付到|付款至|付款到|打入|打到|存入"
                     r"|结算至|结算到|缴至|缴入|汇款至|汇款到|向[^，。！？；]{0,12}(?:账户|帐户|账号|收款单位)(?:付款|汇款|转账|支付)")
_PAY_HEAD_ZH = re.compile(r"请|务必|需|需要|即可|立即|马上|尽快|直接|麻烦|烦请")
_UNCHANGED_ZH = re.compile(r"原有的?账户|原账户|原来的账户|现有账户")
_BYPASS_ZH = re.compile(r"无需[^，。！？；]{0,4}(?:致电|电话|打电话|来电)?(?:核实|确认|核对|联系)|不要(?:致电|打电话|来电|联系)|保密"
                        r"|不要(?:告诉|告知)(?:他人|其他人|任何人)|不要再?使用原(?:有|来的?)?(?:账户|帐户|账号)"
                        r"|电话(?:暂时)?(?:无法接通|故障|打不通)|(?:此事|变更)(?:很|非常)?紧急")
_KNOWN_CHANNEL_ZH = re.compile(r"(?:已有|已知|原有|您手中)的?[^，。！？；]{0,10}(?:电话|号码|联系方式)[^，。！？；]{0,10}(?:核实|确认|核对)"
                               r"|(?:核实|确认|核对)[^，。！？；]{0,10}(?:已有|已知|原有)的?[^，。！？；]{0,6}(?:电话|号码)"
                               r"|当面(?:确认|核实)|致电[^，。！？；]{0,10}(?:已有|已知)")


def _changed_destination(sentence: str) -> bool:
    if _CHANGED_EN.search(sentence) or _CHANGED_ZH.search(sentence):
        return True
    if any(not _NOT_A_PAYEE_EN.search(sentence[max(0, match.start() - 16):match.start()])
           for match in _NEW_TARGET_EN.finditer(sentence)):
        return True
    return any(not _NOT_A_PAYEE_ZH.search(sentence[:match.start()]) for match in _NEW_TARGET_ZH.finditer(sentence))


def _pay_request(sentence: str) -> bool:
    """A request to the reader to pay, not to an account that has not changed."""
    for match in _PAY_EN.finditer(sentence):
        if not _HEAD_EN.search(sentence[:match.start()]):
            continue
        rest = sentence[match.start():]
        end = _SPAN_END_EN.search(rest, len(match.group(0)))
        clause = rest[:end.start()] if end else rest
        if not _UNCHANGED_EN.search(clause) or _changed_destination(clause):
            return True
    if _PAY_PASSIVE_EN.search(sentence):
        return True
    for clause in _CLAUSE_ZH.split(sentence):
        for match in _PAY_ZH.finditer(clause):
            head = clause[:match.start()]
            if _NEGATION_ZH.search(head) or not _PAY_HEAD_ZH.search(head):
                continue
            if not _UNCHANGED_ZH.search(clause[match.start():]) or _changed_destination(clause):
                return True
    return False


def _payment_bypass(clause: str) -> bool:
    if _BYPASS_EN.search(clause):
        return True
    if _BYPASS_ZH.search(clause):
        return True
    if re.search(r"(?:请)?(?:勿|不要)(?:致电|打电话)[^，。！？；]{0,4}(?:确认|核实|核对)", clause):
        return True
    return False

def _payment_change(clause: str) -> bool:
    if _changed_destination(clause):
        return True
    if re.search(r"\u66ff\u6362\u7684\u6536\u6b3e\u4fe1\u606f|\u66ff\u6362\u7684\u6536\u6b3e\u4eba\u5750\u6807", clause):
        return True
    if re.search(r"(?:银行信息|付款信息|收款信息)\s*(?:已经|现已|已)\s*(?:更改|变更|更换|更新)", clause):
        return True
    return False

def _known_payment_check(clause: str) -> bool:
    known = bool(_KNOWN_CHANNEL_EN.search(clause) or _KNOWN_CHANNEL_ZH.search(clause))
    if not known:
        known = bool(re.search(r"number you already have[^.;!?\u3002\uff01\uff1f\uff1b]{0,80}?(confirm|verify)|\u60a8\u5df2\u6709\u7684\u7535\u8bdd\u53f7\u7801[^.;!?\u3002\uff01\uff1f\uff1b]{0,80}?(\u786e\u8ba4|\u6838\u5b9e)", clause, re.I))
    related = bool(re.search(r"bank|payment|invoice|beneficiary|account details|this change|these details|\u6536\u6b3e|\u8d26\u6237\u53d8\u66f4|\u8fd9\u6b21\u53d8\u66f4|\u6b64\u53d8\u66f4|\u6b64\u66f4\u6539|\u8fd9\u6b21\u66f4\u6539|\u672c\u6b21\u53d8\u66f4", clause, re.I))
    unrelated = bool(re.search(r"shipping|delivery|\u914d\u9001|\u53d1\u8d27|support only", clause, re.I))
    return bool(known and related and not unrelated)

def payment_redirection(text: str) -> bool:
    direct = [(clause, sidx) for clause, sidx, reported in _request_units(text) if not reported]
    for changed_clause, changed_sidx in direct:
        if not _payment_change(changed_clause):
            continue
        window = [(c, i) for c, i in direct if abs(i - changed_sidx) <= 1]
        bypass = any(_payment_bypass(c) for c, _ in window)
        if bypass:
            return True
        known = any(_known_payment_check(c) for c, _ in window)
        if known:
            continue
        for pay_clause, _ in window:
            if not _pay_request(pay_clause):
                continue
            if (_UNCHANGED_EN.search(pay_clause) or _UNCHANGED_ZH.search(pay_clause)) and not _payment_change(pay_clause):
                continue
            if pay_clause is changed_clause or _payment_change(pay_clause) or _PAYMENT_REFERENCE_RE.search(pay_clause):
                return True
    return False


def intent_findings(readings, links, sender_domain: str = '', display_name: str = '') -> list[dict]:
    """Return enabled intent findings, materializing readings once and processing each independently."""
    enabled = ENABLED.get()
    if not enabled:
        return []
    # Materialize readings once
    materialized = list(readings)
    found = []
    if 'credential' in enabled:
        for text, labelled_links in materialized:
            if credential_handover(text, labelled_links, sender_domain, display_name):
                found.append(indicator('medium', CODES['credential']))
                break
    if 'payment' in enabled:
        for text, _labelled in materialized:
            if payment_redirection(text):
                found.append(indicator('medium', CODES['payment']))
                break
    return found


_CAP_REQUEST_RE = re.compile(r"(?:Please|Kindly|Reply|Respond|Send|Provide|Give|Tell|Read|Enter|Re-enter|Type|Confirm|Verify|Pay|Wire|Transfer|Remit|Settle|Change|Update|Switch)\b")
_TAIL_NEGATION_RE = re.compile(r"\b(?:never|not|without|do\s+not|don['’]t|no\s+need\s+to)\s*$", re.IGNORECASE)
_INLINE_FORWARD_RE = re.compile(r"-{3,}\s*(?:forwarded|original)\s+message\s*-{3,}|(?:-{3,}\s*)?(?:转发(?:的)?邮件|原始邮件)\s*[:：]?\s*(?:-{3,})?", re.IGNORECASE)
_REFERENCE_ONLY_RE = re.compile(r"\b(?:docs?|documentation|help|shipping|supporting\s+information)\b|文档|帮助|配送", re.IGNORECASE)
_LOCAL_PAGE_REFERENCE_RE = re.compile(r"\b(?:below|following|next|here|this\s+(?:link|page)|that\s+page)\b|下方|以下|如下|此处|这个链接|该页面", re.IGNORECASE)
_PAYMENT_REFERENCE_RE = re.compile(
    rf"\b(?:there|it|that\s+(?:account|destination)|these\s+(?:details|coordinates)|(?:this|the)\s+(?:new|replacement)\s+(?:account|destination))\b"
    rf"|(?:{_MONEY_TARGET_EN})|{_MONEY_TARGET_ZH}|该账户|那里|上述"
    r"|\b(?:all\s+)?future\s+(?:payments?|remittances?|wires?)\b", re.IGNORECASE)


_ENTRY_PAGE_CONTEXT_RE = re.compile(r"\b(?:(?:review|verification|login|sign[\s-]?in|account|secure)\s+(?:page|portal|site|form)|entry\s+page)\b|登录页面|验证页面|核验页面|账户页面|审核页面", re.IGNORECASE)


_POLITE_PREFIX_ONLY_RE = re.compile(r"\s*(?:(?:please|kindly|simply|just|now|then|first|also)\b\s*)+", re.IGNORECASE)



