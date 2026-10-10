"""Domain and mailbox checks behind /api/verify-email: MX discovery, SPF, DMARC, MX reverse DNS,
WHOIS domain age and the optional SMTP RCPT probe (local full mode only).

Each check returns a dict with an English message plus its stable code and parameters
(server_messages.py). app.py owns the endpoint, its worker pool and deadline.
"""
from __future__ import annotations

import ipaddress
import re
import smtplib
import socket
import time

from server_messages import message as coded_message


def _verify_message(code: str, key: str = 'message', **params) -> dict:
    """An English verification message plus its stable code and parameters.

    ``message`` gets ``code``/``params``; another field (``smtp_message``,
    ``note``, ``reason``) gets ``<field>_code``/``<field>_params``.
    """
    coded = coded_message(code, **params)
    prefix = '' if key == 'message' else key + '_'
    return {key: coded['msg'], prefix + 'code': code, prefix + 'params': coded['params']}


# ── Helper: SMTP mailbox probe ────────────────────────────────────────────────
def _resolve_public_smtp_addresses(
    mx_host: str,
    *,
    resolver=None,
    timeout: float = 5,
) -> list[str]:
    """Resolve a mail host once and retain only globally routable targets."""
    addresses: list[str] = []
    if resolver is None:
        import dns.resolver
        import dns.exception
        answers = []
        deadline = time.monotonic() + timeout
        for kind in ('A', 'AAAA'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                records = dns.resolver.resolve(mx_host, kind, lifetime=remaining)
                answers.extend((None, None, None, None, (str(r), 25)) for r in records)
            except dns.exception.DNSException:
                continue
    else:
        try:
            answers = resolver(mx_host, 25, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            return addresses

    for _family, _socktype, _proto, _canonname, sockaddr in answers:
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            is_global = ipaddress.ip_address(address).is_global
        except ValueError:
            continue
        if is_global and address not in addresses:
            addresses.append(address)
    return addresses


def _smtp_probe(
    email: str,
    mx_host: str,
    smtp_address: str | None = None,
    timeout: int = 8,
) -> dict:
    result = {"connectable": False, "result": "unverifiable", "message": "", "code": None, "params": {},
              "status": "error"}
    deadline = time.monotonic() + timeout
    if smtp_address is None:
        public_addresses = _resolve_public_smtp_addresses(mx_host, timeout=min(5, timeout))
        smtp_address = public_addresses[0] if public_addresses else None
    try:
        is_public_target = bool(
            smtp_address and ipaddress.ip_address(smtp_address).is_global
        )
    except ValueError:
        is_public_target = False
    if not is_public_target:
        result['status'] = 'unavailable'
        result.update(_verify_message('verify.smtp_non_public_target', host=mx_host))
        return result

    smtp = None
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise socket.timeout()
        return seconds
    try:
        smtp = smtplib.SMTP(timeout=remaining())
        smtp.connect(smtp_address, 25)
        result["connectable"] = True
        smtp.sock.settimeout(remaining())
        smtp.helo("verify.phishguard.local")
        smtp.sock.settimeout(remaining())
        smtp.mail("")
        smtp.sock.settimeout(remaining())
        code, msg_bytes = smtp.rcpt(email)
        result['status'] = 'ok'
        msg_str = msg_bytes.decode(errors="replace") if isinstance(msg_bytes, bytes) else str(msg_bytes)
        enhanced_match = re.match(r'^\s*([245]\.\d{1,3}\.\d{1,3})(?:\s|$)', msg_str)
        enhanced = enhanced_match.group(1) if enhanced_match else None
        try:
            smtp.sock.settimeout(remaining())
            smtp.quit()
        except Exception:
            pass
        if code == 250:
            result["result"] = "exists"
            result.update(_verify_message('verify.smtp_accepted', smtp_code=code))
        elif 500 <= code < 600 and enhanced == '5.1.1':
            result["result"] = "does_not_exist"
            result.update(_verify_message('verify.smtp_no_such_mailbox', smtp_code=code, response=msg_str[:120]))
        elif 500 <= code < 600 and enhanced and enhanced.startswith('5.7.'):
            result['result'] = 'policy_rejected'
            result.update(_verify_message('verify.smtp_policy_rejected', smtp_code=code, response=msg_str[:120]))
        elif 500 <= code < 600 and enhanced == '5.2.2':
            result['result'] = 'mailbox_full'
            result.update(_verify_message('verify.smtp_mailbox_full', smtp_code=code, response=msg_str[:120]))
        elif code in (421, 450, 451, 452):
            result["result"] = "temporarily_unavailable"
            result.update(_verify_message('verify.smtp_temporary_error', smtp_code=code))
        else:
            result["result"] = "unknown"
            result.update(_verify_message('verify.smtp_inconclusive', smtp_code=code, response=msg_str[:120]))
    except smtplib.SMTPConnectError as e:
        result.update(_verify_message('verify.smtp_connect_failed', host=mx_host, error=str(e)))
    except smtplib.SMTPServerDisconnected as e:
        result.update(_verify_message('verify.smtp_disconnected', error=str(e)))
    except socket.timeout:
        result['status'] = 'timeout'
        result.update(_verify_message('verify.smtp_connection_timeout', host=mx_host, seconds=timeout))
    except OSError as e:
        result.update(_verify_message('verify.smtp_network_error', error=str(e)))
    except Exception as e:
        result.update(_verify_message('verify.smtp_error', error=str(e)[:150]))
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
    return result


# ── Helper: SPF record check ──────────────────────────────────────────────────
def _check_spf(domain: str) -> dict:
    """Look up SPF TXT record and parse the enforcement policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v=spf1(?:\s|$)', txt, re.IGNORECASE)]
        if len(records) > 1:
            raise ValueError('Multiple SPF records; policy is inconclusive')
        for txt in records:
            terms = txt.split()
            if terms and terms[0].lower() == 'v=spf1':
                # Validate local term shapes before summarizing the first all.
                # This does not expand macros or evaluate include/redirect.
                mechanism = (r'[+?~-]?(?:all|(?:include|exists):\S+|'
                             r'(?:a|mx)(?::\S+|/[0-9]+(?://[0-9]+)?|//[0-9]+)?|'
                             r'ptr(?::\S+)?|ip[46]:\S+)')
                modifier = r'[a-z][a-z0-9._-]*=\S+'
                if any(not re.fullmatch(mechanism + '|' + modifier, term, re.IGNORECASE)
                       for term in terms[1:]):
                    raise ValueError('Malformed or unsupported SPF mechanism')
                result['status'] = 'ok'
                result["found"]  = True
                result["record"] = txt[:250]
                all_term = next((term.lower() for term in terms[1:]
                                 if re.fullmatch(r'[+?~-]?all', term, re.IGNORECASE)), None)
                if all_term == '-all':
                    result["policy"]  = "strict"
                    result.update(_verify_message('verify.spf_strict'))
                elif all_term == '~all':
                    result["policy"]  = "softfail"
                    result.update(_verify_message('verify.spf_softfail'))
                elif all_term == '?all':
                    result["policy"]  = "neutral"
                    result.update(_verify_message('verify.spf_neutral'))
                elif all_term in {'+all', 'all'}:
                    result["policy"]  = "open"
                    result.update(_verify_message('verify.spf_open'))
                else:
                    result["policy"]  = "unknown"
                    result.update(_verify_message('verify.spf_unclear'))
                break
        if not result["found"]:
            result.update(_verify_message('verify.spf_missing'))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.no_txt_records'))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.dns_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.spf_error', error=str(e)[:100]))
    return result


# ── Helper: DMARC policy check ────────────────────────────────────────────────
def _check_dmarc(domain: str) -> dict:
    """Look up DMARC TXT record at _dmarc.<domain> and parse the p= policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "pct": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v\s*=\s*DMARC1\s*(?:;|$)', txt)]
        if len(records) > 1:
            raise ValueError('Multiple DMARC records; policy is inconclusive')
        for txt in records:
            result['found'] = True
            result['record'] = txt[:250]
            tags = {}
            for field in txt.rstrip().rstrip(';').split(';'):
                match = re.fullmatch(r'\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*(.*?)\s*', field)
                if not match or match.group(1) in tags:
                    raise ValueError('Malformed or duplicate DMARC tag')
                tags[match.group(1)] = match.group(2)
            p = tags.get('p')
            if p not in {'reject', 'quarantine', 'none'}:
                raise ValueError('Missing or invalid DMARC p= policy')
            pct_text = tags.get('pct', '100')
            if not re.fullmatch(r'[0-9]{1,3}', pct_text) or int(pct_text) > 100:
                raise ValueError('DMARC pct must be between 0 and 100')
            pct = int(pct_text)
            result.update(status='ok', policy=p, pct=pct)
            # p=none never mentions pct; a partial pct names its percentage.
            partial = pct < 100 and p != 'none'
            result.update(_verify_message(f'verify.dmarc_{p}{"_partial" if partial else ""}',
                                          **({'pct': pct} if partial else {})))
        if not result["found"]:
            result.update(_verify_message('verify.dmarc_missing', domain=domain))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.dmarc_not_found', domain=domain))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.dns_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.dmarc_error', error=str(e)[:100]))
    return result


# ── Helper: Domain age via WHOIS ──────────────────────────────────────────────
def _check_domain_age(domain: str) -> dict:
    """Retrieve domain creation date via WHOIS and assess age."""
    result = {"found": False, "creation_date": None, "age_days": None,
              "registrar": None, "message": "", "code": None, "params": {}, "status": "not_found"}
    try:
        import whois
        from datetime import datetime, timezone
        w = whois.whois(domain, timeout=5)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now - creation).days
            result["found"]         = True
            result['status'] = 'ok'
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["age_days"]      = age
            result["registrar"]     = (w.registrar or "")[:80] if w.registrar else None
            if age < 30:
                result.update(_verify_message('verify.age_very_new', days=age))
            elif age < 180:
                result.update(_verify_message('verify.age_new', days=age, months=age // 30))
            elif age < 365:
                result.update(_verify_message('verify.age_under_year', days=age))
            else:
                years = age // 365
                result.update(_verify_message(
                    'verify.age_established' if years != 1 else 'verify.age_established_one',
                    date=creation.strftime('%Y-%m-%d'), years=years))
        else:
            result.update(_verify_message('verify.age_no_date'))
    except Exception as e:
        result['status'] = 'timeout' if isinstance(e, TimeoutError) else 'error'
        result.update(_verify_message('verify.age_failed', error=str(e)[:100]))
    return result


# ── Helper: MX PTR (reverse DNS) check ───────────────────────────────────────
def _check_mx_ptr(mx_host: str) -> dict:
    """Check if the primary MX server has a valid PTR (reverse DNS) record."""
    import dns.resolver, dns.reversename, dns.exception
    result = {"found": False, "ptr": None, "ip": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        a_records = dns.resolver.resolve(mx_host, "A", lifetime=5)
        ip = str(a_records[0])
        result["ip"] = ip
        rev = dns.reversename.from_address(ip)
        ptr_records = dns.resolver.resolve(rev, "PTR", lifetime=5)
        ptr = str(ptr_records[0]).rstrip(".")
        result["found"] = True
        result["ptr"]   = ptr
        result['status'] = 'ok'
        result.update(_verify_message('verify.ptr_found', ip=ip, ptr=ptr))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.ptr_missing_ip', ip=result['ip']) if result['ip']
                      else _verify_message('verify.ptr_missing'))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.ptr_lookup_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.ptr_error', error=str(e)[:100]))
    return result


def _lookup_mail_domain(domain: str, deadline: float) -> dict:
    """Perform bounded DNS discovery; a timeout is not a nonexistent mailbox."""
    import dns.resolver
    import dns.exception
    result = {'mx_found': False, 'mx_records': [], 'overall': 'unverifiable',
              **_verify_message('verify.dns_timeout', 'smtp_message')}
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        answers = dns.resolver.resolve(domain, 'MX', lifetime=min(6, remaining))
        records = sorted((r.preference, str(r.exchange).rstrip('.')) for r in answers)
        if any(not host for _, host in records):
            if records == [(0, '')]:
                return {**result, 'null_mx': True, 'overall': 'no_mail_service',
                        **_verify_message('verify.null_mx', 'smtp_message')}
            return {**result, **_verify_message('verify.invalid_null_mx', 'smtp_message')}
        if records:
            return {'mx_found': True, 'mx_records': records}
    except dns.resolver.NXDOMAIN:
        return {**result, 'overall': 'likely_invalid', **_verify_message('verify.domain_not_found', 'smtp_message')}
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        return result
    address_lookup_failed = False
    for kind in ('A', 'AAAA'):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        try:
            addresses = dns.resolver.resolve(domain, kind, lifetime=min(4, remaining))
            if addresses:
                return {'mx_found': True, 'mx_records': [[0, domain]],
                        **_verify_message('verify.address_record_fallback', 'note', record_type=kind)}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            address_lookup_failed = True
    if address_lookup_failed:
        return result
    return {**result, 'overall': 'likely_invalid', **_verify_message('verify.no_mail_records', 'smtp_message')}


def _summarize_verification(out: dict, *, smtp_enabled: bool) -> None:
    """Add explicit domain/mailbox summaries without overstating evidence."""
    domain_complete = False
    if not out["format_valid"]:
        domain_status = "invalid_format"
    elif out["null_mx"]:
        domain_status = "no_mail_service"
    elif out["mx_found"]:
        domain_checks = (out["spf"], out["dmarc"], out["domain_age"], out["mx_ptr"])
        domain_complete = all(
            info is not None and info.get("status") in {"ok", "not_found"}
            for info in domain_checks
        )
        domain_status = "valid" if domain_complete else "partial"
    elif out["overall"] == "likely_invalid":
        domain_status = "invalid"
    else:
        domain_status = "unavailable"

    # The reason repeats smtp_message (or the disabled notice) with its code.
    reason = {'reason': out["smtp_message"], 'reason_code': out.get("smtp_message_code"),
              'reason_params': out.get("smtp_message_params") or {}}
    if not smtp_enabled:
        mailbox_status = "unavailable"
        reason = _verify_message('verify.smtp_disabled_reason', 'reason')
    elif out["smtp_result"] == "exists":
        mailbox_status = "accepted"
    elif out["smtp_result"] == "does_not_exist":
        mailbox_status = "rejected"
    else:
        mailbox_status = "inconclusive"

    out["domain_verification"] = {
        "status": domain_status,
        "complete": domain_complete,
        "mx_found": out["mx_found"],
    }
    out["mailbox_verification"] = {
        "status": mailbox_status,
        **reason,
    }
    out["verification_complete"] = (
        domain_complete and mailbox_status in {"accepted", "rejected"}
    )
