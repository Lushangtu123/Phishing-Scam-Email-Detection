"""How an HTML email renders as text: the HTML parser base, Outlook conditional comments,
the CSS cascade, colours and the text each plausible rendering shows.

Moved verbatim out of app.py on 2026-10-05 so the visibility reader can be read and
tested on its own; app.py imports what it uses from here.
"""

from __future__ import annotations

import math
import re
import unicodedata
from functools import lru_cache
from html import escape as escape_html, unescape as unescape_html
from html.parser import HTMLParser
from itertools import product, takewhile
from urllib.parse import urljoin, urlparse

from language_coverage import non_latin_script_segments
from server_messages import text as message_text


def _parse_link_target(destination: str, *, base: str | None = None):
    destination = re.sub(r'[\t\r\n]', '', destination.strip())
    destination = re.sub(r'^hxxp(s?)://', r'http\1://', destination, flags=re.IGNORECASE)
    scheme = re.match(r'^([a-z][a-z0-9+.-]*):', destination, re.IGNORECASE)
    if not scheme or scheme.group(1).lower() in {'http', 'https'}:
        # HTTP(S) uses backslashes as separators, but not inside query/fragment.
        # Normalize authority slashes BEFORE joining a base, otherwise urljoin
        # can turn an external host into an apparently same-origin path.
        pieces = re.split(r'([?#])', destination, maxsplit=1)
        pieces[0] = pieces[0].replace('\\', '/')
        destination = ''.join(pieces)
        if scheme:
            protocol = scheme.group(1).lower()
            rest = destination[scheme.end():]
            if not base or protocol != urlparse(base).scheme or rest.startswith('//'):
                destination = protocol + '://' + rest.lstrip('/')
        elif destination.startswith('//'):
            destination = '//' + destination.lstrip('/')
            if not base:
                destination = 'https:' + destination
    if (destination.startswith('//') or re.match(r'^https?://', destination, re.IGNORECASE)):
        if not urlparse(destination).hostname:
            raise ValueError('Explicit HTTP(S) authority has no host')
    if base:
        destination = urljoin(base, destination)
    parsed = urlparse(destination)
    if parsed.scheme in {'http', 'https'}:
        if not parsed.hostname:
            raise ValueError('HTTP(S) destination has no host')
        _ = parsed.port  # Validate ports as well as bracketed address syntax.
    return parsed


def _strip_invisible_format_controls(text: str) -> str:
    """Remove zero-width formatting controls commonly used to split keywords."""
    return "".join(character for character in text if unicodedata.category(character) != "Cf")


def _first_html_attributes(attrs):
    """Use HTML's first occurrence of each attribute, including empty values."""
    attributes = {}
    for name, value in attrs:
        attributes.setdefault(name, value)
    return attributes


class _AnalysisHTMLParser(HTMLParser):
    _marked_declaration = re.compile(r'<!\[([a-zA-Z][-_.a-zA-Z0-9]*)')
    _literal_elements = {'textarea', 'title', 'xmp'}
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, *_literal_elements)

    def set_cdata_mode(self, elem, *, escapable=False):
        # New CPython patch releases pass escapable here. Keep the base parser
        # in raw mode: handle_data owns the one-time RCDATA decoding below.
        # Omitting the keyword also supports older HTMLParser signatures.
        super().set_cdata_mode(elem)
        if elem in self._literal_elements:
            # Only the matching HTML end-tag name leaves RCDATA/RAWTEXT.
            # In particular, </textareax> and </ textarea> remain literal.
            self.interesting = re.compile(r'</' + elem + r'(?=[\t\n\f\r />])', re.I | re.ASCII)

    def parse_endtag(self, index):
        if self.cdata_elem in self._literal_elements:
            # End tags may have (ignored) attributes or a trailing slash. Keep
            # quoted '>' characters inside those attributes, including when
            # input arrives in separate feed() calls.
            ending = re.match(r'''</[a-z]+(?=[\t\n\f\r />])(?:[^'">]|"[^"]*"|'[^']*')*>''',
                              self.rawdata[index:], re.I | re.ASCII)
            if ending is None:
                return -1
            self.handle_endtag(self.cdata_elem)
            self.clear_cdata_mode()
            return index + ending.end()
        return super().parse_endtag(index)

    def handle_startendtag(self, tag, attrs):
        # A self-closing slash does not close a non-void HTML element.
        self.handle_starttag(tag, attrs)
        if tag in _HTML_VOID_ELEMENTS:
            self.handle_endtag(tag)
        elif tag in self.CDATA_CONTENT_ELEMENTS:
            self.set_cdata_mode(tag)

    def handle_data(self, data):
        # RCDATA decodes references once; RAWTEXT preserves them literally.
        # Collectors receive text tokens, never reparse them as nested markup.
        self.collect_data(unescape_html(data) if self.cdata_elem in {'textarea', 'title'} else data)

    def collect_data(self, data):
        pass

    def goahead(self, end):
        super().goahead(end)
        if end and self.cdata_elem in self._literal_elements and self.rawdata:
            # HTMLParser buffers unclosed CDATA even at EOF. A visible textarea
            # or xmp still has text in that case, so do not silently drop it.
            self.handle_data(self.rawdata)
            self.updatepos(0, len(self.rawdata))
            self.rawdata = ''

    def parse_html_declaration(self, index):
        # Recent CPython versions silently consume unknown marked declarations
        # as bogus comments. Detect them at the parser boundary, not by scanning
        # raw HTML (which would also match comments, attributes and scripts).
        if self.rawdata.startswith('<![', index):
            match = self._marked_declaration.match(self.rawdata, index)
            if not match or match.group(1).lower() not in {
                'temp', 'cdata', 'ignore', 'include', 'rcdata', 'if', 'else', 'endif',
            }:
                raise ValueError('Unrecognized HTML marked declaration')
        return super().parse_html_declaration(index)


_MSO_CONDITIONAL_WARNING = message_text('warning.mso_conditional')


# Private-use sentinels that bracket Outlook-only content (U+E000/U+E001) and content
# hidden from Outlook (U+E002/U+E003) in the rendering-view pass only.
_RENDERING_SENTINELS = re.compile('[\ue000-\ue003]')


def _expand_mso_comments(text: str, parse_warnings=None, *, mark=False, unresolved=None) -> str:
    """Expose one bounded layer of conditional markup to every HTML collector.

    Parse actual comment tokens, not comment-like strings in attributes/scripts.
    The expanded document is evidence only, not a verified client rendering.
    Nested or malformed branches retain the incomplete-analysis warning.
    With mark, Outlook-only and Outlook-hidden content is bracketed by sentinels,
    and a branch that cannot be bracketed is appended to unresolved.
    """
    if mark:
        text = _RENDERING_SENTINELS.sub('', text)
    comment_end = re.compile(r'--\s*>')
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer(r'\n', text))

    class ConditionalComments(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.replacements = []
            self.hidden_from_outlook = 0

        def _span(self):
            line, column = self.getpos()
            start = offsets[line - 1] + column
            close = comment_end.search(text, start + 4)
            return start, close.end() if close else None

        def handle_comment(self, data):
            if mark and data.strip() == '<![endif]' and self.hidden_from_outlook:
                # Closes <!--[if !mso]><!--> ... : the content between was hidden from Outlook.
                self.hidden_from_outlook -= 1
                start, _end = self._span()
                self.replacements.append((start, start, '\ue003'))
                return
            opening = re.match(r'\[if\s+([^\]]+)\]>', data.strip(), re.IGNORECASE)
            if not opening or not re.search(r'\bmso\b', opening.group(1), re.IGNORECASE):
                return
            condition = re.sub(r'\s+', '', opening.group(1).casefold())
            if (condition.count('(') == condition.count(')')
                    and re.fullmatch(r'\(*(?:!|not)\(*mso\)*', condition)):
                if mark and re.fullmatch(r'\[if\s+[^\]]+\]><!', data.strip(), re.IGNORECASE):
                    _start, end = self._span()
                    if end is None:
                        unresolved.append('conditional')
                        return
                    self.hidden_from_outlook += 1
                    self.replacements.append((end, end, '\ue002'))
                return
            if parse_warnings is not None and _MSO_CONDITIONAL_WARNING not in parse_warnings:
                parse_warnings.append(_MSO_CONDITIONAL_WARNING)
            # Formatters may wrap the closing tag: "<!" and "[endif]" on separate lines.
            conditional = re.fullmatch(r'\[if\s+[^\]]+\]>(.*?)<!\s*\[endif\s*\]',
                                       data.strip(), flags=re.IGNORECASE | re.DOTALL)
            if not conditional:
                # <!--[if mso]><!--> content <!--<![endif]--> shows everywhere; any other
                # unexpanded branch leaves an Outlook view the text pass cannot see.
                if mark and not re.fullmatch(r'\[if\s+[^\]]+\]><!', data.strip(), re.IGNORECASE):
                    unresolved.append('conditional')
                return
            start, end = self._span()
            if end is not None:
                content = f'\ue000{conditional.group(1)}\ue001' if mark else conditional.group(1)
                self.replacements.append((start, end, content))
            elif mark:
                unresolved.append('conditional')

    scanner = ConditionalComments()
    scanner.feed(text)
    scanner.close()
    if mark and scanner.hidden_from_outlook:
        unresolved.append('conditional')
    parts = []
    cursor = 0
    for start, end, content in scanner.replacements:
        parts.extend((text[cursor:start], content))
        cursor = end
    parts.append(text[cursor:])
    return ''.join(parts)


def _collect_html(factory, text: str, parse_warnings=None, *, mark=False, unresolved=None):
    collector = factory()
    try:
        collector.feed(_expand_mso_comments(text, parse_warnings, mark=mark, unresolved=unresolved))
        collector.close()
    except (AssertionError, ValueError):
        warning = message_text('warning.malformed_html')
        if parse_warnings is not None and warning not in parse_warnings:
            parse_warnings.append(warning)
        if unresolved is not None:
            unresolved.append('malformed')
        # Neutralize broken marked declarations, then start fresh so partially
        # collected text/forms/links are neither duplicated nor allowed to hide
        # the rest of the document. Final fallback is literal text, not success.
        collector = factory()
        try:
            collector.feed(_expand_mso_comments(text.replace('<![', '&lt;!['), parse_warnings,
                                                mark=mark, unresolved=unresolved))
            collector.close()
        except (AssertionError, ValueError):
            collector = factory()
            collector.feed(escape_html(text))
            collector.close()
    return collector


_HIDDEN_HTML_TEXT_WARNING = message_text('warning.hidden_html_text')
_STYLESHEET_VISIBILITY_WARNING = message_text('warning.stylesheet_visibility')
_INLINE_CSS_VISIBILITY_WARNING = message_text('warning.inline_css_visibility')
# Text that may be invisible (a tiny font, near-zero opacity, clipped by its box, off
# screen, mso-hide): text rules read the message both with and without it, unlike
# CSS-uncertain text, whose prose only the floor-setting request and lure rules read, as
# text the message may hide (analyze_email_content).
_POSSIBLY_INVISIBLE_WARNING = message_text('warning.possibly_invisible_text')
_IMAGE_ALT_FALLBACK_WARNING = message_text('warning.image_alt_fallback')


_HTML_VOID_ELEMENTS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
    'param', 'source', 'track', 'wbr',
}
_P_IMPLIED_END_START_TAGS = {
    'address', 'article', 'aside', 'blockquote', 'details', 'dialog', 'div',
    'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2',
    'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav',
    'ol', 'p', 'pre', 'search', 'section', 'table', 'ul',
}


_CSS_NUMBER = r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?'
_CSS_WIDE_KEYWORDS = frozenset({'inherit', 'initial', 'unset', 'revert', 'revert-layer'})
_DISPLAY_KEYWORDS = frozenset('''
    none contents block inline run-in flow flow-root table flex grid ruby list-item math grid-lanes
    inline-block inline-table inline-flex inline-grid inline-list-item inline-grid-lanes
    table-row-group table-header-group table-footer-group table-row table-cell table-column-group table-column
    table-caption ruby-base ruby-text ruby-base-container ruby-text-container
    -webkit-box -webkit-inline-box -webkit-flex -webkit-inline-flex -moz-box -moz-inline-box -moz-inline-stack
    -ms-flexbox -ms-inline-flexbox -ms-grid -ms-inline-grid'''.split()) | _CSS_WIDE_KEYWORDS
_DISPLAY_MULTI_KEYWORDS = frozenset('block inline run-in flow flow-root table flex grid ruby list-item'.split())


def _recognised_visibility_value(name: str, value: str) -> bool:
    """Whether a display, visibility or opacity value is one this reader knows. An opacity
    from var() is resolved element by element."""
    if name == 'display':
        words = value.split()
        return value in _DISPLAY_KEYWORDS or (1 < len(words) <= 3 and set(words) <= _DISPLAY_MULTI_KEYWORDS)
    if name == 'visibility':
        return value in {'visible', 'hidden', 'collapse'} | _CSS_WIDE_KEYWORDS
    if name == 'opacity':
        return (value in _CSS_WIDE_KEYWORDS or value.startswith(('calc(', 'var('))
                or bool(re.fullmatch(_CSS_NUMBER + '%?', value)))
    return True


def _style_values(style: str) -> dict[str, tuple[str, bool]]:
    """Visibility-related declarations of one style: name -> (value, !important).

    An unknown display, visibility or opacity value does not replace an earlier one, and
    is recorded under '#unrecognised': a browser drops it if it is invalid but applies it
    if it is a value this reader does not know, so the text it reaches stays unresolved.
    """
    # A semicolon inside quoted content, url(), or a CSS escape is not a
    # declaration boundary. Splitting it blindly can hide genuinely visible
    # text when an unrelated property contains the string "; display:none".
    declarations = []
    current = []
    quote = None
    depth = 0
    index = 0
    while index < len(style):
        character = style[index]
        following = style[index + 1] if index + 1 < len(style) else ''
        if quote:
            current.append(character)
            if character == '\\' and following:
                current.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = style.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character == '\\' and following:
            current.extend((character, following))
            index += 1
        elif character in {'"', "'"}:
            quote = character
            current.append(character)
        elif character == '(':
            depth += 1
            current.append(character)
        elif character == ')':
            depth = max(0, depth - 1)
            current.append(character)
        elif character == ';' and depth == 0:
            declarations.append(''.join(current))
            current = []
        else:
            current.append(character)
        index += 1
    declarations.append(''.join(current))
    values = {}
    for declaration in declarations:
        name, separator, value = declaration.partition(':')
        name = _unescape_css(name).strip()
        # Custom properties (--name) keep their case; other names are case-insensitive.
        name = name if name.startswith('--') else name.lower()
        if not separator or not (name.startswith('--') or name in {
                'display', 'visibility', 'opacity', 'font-size', 'color', *_GEOMETRY_PROPERTIES,
                'background', 'background-color', 'background-image', 'background-clip', '-webkit-background-clip',
                'background-size', 'background-repeat'}):
            continue
        # Browsers read the prefixed name as the same property.
        name = 'background-clip' if name == '-webkit-background-clip' else name
        # Values are case-insensitive, except the names of custom properties (var(--Name)).
        # Any run of whitespace is one space to CSS: rgb(255,\n255,255) is white.
        value = ''.join(part if part.startswith('--') else part.lower()
                        for part in re.split(r'((?<![\w-])--[\w-]+)',
                                             re.sub(r'\s+', ' ', _unescape_css(value)).strip()))
        important = bool(re.search(r'!\s*important\s*$', value))
        value = re.sub(r'!\s*important\s*$', '', value).strip()
        # CSS drops an invalid declaration, so an earlier valid one still applies:
        # color:transparent; color:rgb(nope) stays transparent.
        if (name in {'color', 'background-color'} and _color_class(value) == 'invalid') or (
                name == 'font-size' and _font_size_class(value) == 'invalid') or (
                name in {'background', 'background-image'} and not _background_valid(value, name)) or (
                name == 'background-clip' and not _background_clip_valid(value)) or (
                name in {'background-size', 'background-repeat'} and not _background_tiling_valid(name, value)):
            continue
        if not _recognised_visibility_value(name, value):
            values['#unrecognised'] = (name, False)
            continue
        # The background shorthand sets the longhands; each reads its own part of it.
        for target in (('background-color', 'background-image', 'background-clip', 'background-size', 'background-repeat')
                       if name == 'background' else (name,)):
            if target not in values or important or not values[target][1]:
                values[target] = (value, important)
    return values


_NAMED_COLORS = frozenset("""
    aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown
    burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan
    darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred
    darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink
    deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold
    goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki lavender lavenderblush
    lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey
    lightpink lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime
    limegreen linen magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen
    mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin
    navajowhite navy oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise
    palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue
    saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue slateblue slategray slategrey snow
    springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen
    accentcolor accentcolortext activetext buttonborder buttonface buttontext canvas canvastext field fieldtext
    graytext highlight highlighttext linktext mark marktext selecteditem selecteditemtext visitedtext
    activeborder activecaption appworkspace background buttonhighlight buttonshadow captiontext
    inactiveborder inactivecaption inactivecaptiontext infobackground infotext menu menutext scrollbar
    threeddarkshadow threedface threedhighlight threedlightshadow threedshadow window windowframe windowtext
    initial
""".split())
_HEX_COLOR = re.compile(r'#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})')
_COLOR_FUNCTION = re.compile(r'(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\((.*)\)')
_COLOR_CHANNEL = rf'(?:{_CSS_NUMBER}%?|none)'
_COLOR_HUE = rf'(?:{_CSS_NUMBER}(?:deg|grad|rad|turn)?|none)'
_COLOR_SPACES = frozenset({'srgb', 'srgb-linear', 'display-p3', 'a98-rgb', 'prophoto-rgb', 'rec2020',
                           'xyz', 'xyz-d50', 'xyz-d65'})
# Values the parser cannot compute: the text they reach stays unresolved.
_UNCOMPUTED = re.compile(r'(?:calc|clamp|min|max|var|env|attr|color-mix|light-dark|if)\(')
# Colours this reader cannot compute: a function that makes one from others or from a
# substitution (color-mix(), light-dark(), var()), a colour function with math or a
# substitution inside, or relative colour syntax (rgb(from red r g b)). A word that only
# holds such a function somewhere ("(min(…)) / 3grad") is no colour.
_UNRESOLVED_COLOR = re.compile(
    r'(?:color-mix|light-dark|contrast-color|device-cmyk|var|env|attr|if)\('
    r'|(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\((?=.*(?:calc|clamp|min|max|round|mod|rem|abs|sign|sin|cos|tan'
    r'|asin|acos|atan|atan2|pow|sqrt|hypot|log|exp|var|env|attr|if)\()'
    r'|[a-z-]+\(\s*from\s', re.S)


def _color_function_alpha(function: str, arguments: str) -> str | None:
    """The alpha of a well-formed colour function ("1" when omitted), or None when malformed.

    Every argument is checked, not only the alpha: rgb(nope) is invalid CSS, so the
    declaration is dropped and the inherited colour stays.
    """
    if ',' in arguments:
        # Legacy comma syntax: rgb()/rgba() with all numbers or all percentages,
        # hsl()/hsla() with a hue and two percentages, then an optional alpha.
        values = [value.strip() for value in arguments.split(',')]
        if len(values) not in (3, 4):
            return None
        if function in {'rgb', 'rgba'}:
            valid = (all(re.fullmatch(_CSS_NUMBER, value) for value in values[:3])
                     or all(re.fullmatch(_CSS_NUMBER + '%', value) for value in values[:3]))
        elif function in {'hsl', 'hsla'}:
            valid = (bool(re.fullmatch(rf'{_CSS_NUMBER}(?:deg|grad|rad|turn)?', values[0]))
                     and all(re.fullmatch(_CSS_NUMBER + '%', value) for value in values[1:3]))
        else:
            valid = False
        if not valid or (len(values) == 4 and not re.fullmatch(_CSS_NUMBER + '%?', values[3])):
            return None
        return values[3] if len(values) == 4 else '1'
    channels, slash, alpha = arguments.partition('/')
    values = channels.split()
    alpha = alpha.strip() if slash else '1'
    if not re.fullmatch(_COLOR_CHANNEL, alpha):
        return None
    if function == 'color':
        if not values or values[0] not in _COLOR_SPACES:
            return None
        values, patterns = values[1:], [_COLOR_CHANNEL] * 3
    elif function in {'hsl', 'hsla', 'hwb'}:
        patterns = [_COLOR_HUE, _COLOR_CHANNEL, _COLOR_CHANNEL]
    elif function in {'lch', 'oklch'}:
        patterns = [_COLOR_CHANNEL, _COLOR_CHANNEL, _COLOR_HUE]
    else:
        patterns = [_COLOR_CHANNEL] * 3
    if len(values) != 3 or not all(re.fullmatch(pattern, value) for value, pattern in zip(values, patterns)):
        return None
    return alpha


def _color_class(color: str) -> str:
    """'transparent', 'visible', 'inherit', 'unresolved' or 'invalid' for one colour value."""
    if not color or color in {'inherit', 'unset', 'revert', 'revert-layer', 'currentcolor'}:
        return 'inherit'
    if _UNRESOLVED_COLOR.match(color):
        return 'unresolved'
    if color == 'transparent':
        return 'transparent'
    if color in _NAMED_COLORS:
        return 'visible'
    if _HEX_COLOR.fullmatch(color):
        digits = color[1:]
        alpha = digits[3] if len(digits) == 4 else digits[6:] if len(digits) == 8 else 'f'
        return 'transparent' if int(alpha, 16) == 0 else 'visible'
    match = _COLOR_FUNCTION.fullmatch(color)
    alpha = match and _color_function_alpha(match.group(1), match.group(2).strip())
    if not alpha:
        return 'invalid'
    # A missing ("none") or negative alpha computes to zero.
    return 'transparent' if alpha == 'none' or float(alpha.rstrip('%')) <= 0 else 'visible'


def _color_state(color: str) -> bool | None:
    """True for a transparent colour, False for a visible one, None to inherit.

    An invalid value is ignored by CSS, so the parent's colour still applies; it must
    not clear an inherited transparent colour.
    """
    return {'transparent': True, 'visible': False}.get(_color_class(color))


# The CSS named colours as 0xRRGGBB. System colours (Canvas, ButtonText) depend on the
# client and are left out.
_NAMED_COLOR_VALUES = {
    'aliceblue': 0xf0f8ff, 'antiquewhite': 0xfaebd7, 'aqua': 0x00ffff, 'aquamarine': 0x7fffd4, 'azure': 0xf0ffff,
    'beige': 0xf5f5dc, 'bisque': 0xffe4c4, 'black': 0x000000, 'blanchedalmond': 0xffebcd, 'blue': 0x0000ff,
    'blueviolet': 0x8a2be2, 'brown': 0xa52a2a, 'burlywood': 0xdeb887, 'cadetblue': 0x5f9ea0,
    'chartreuse': 0x7fff00, 'chocolate': 0xd2691e, 'coral': 0xff7f50, 'cornflowerblue': 0x6495ed,
    'cornsilk': 0xfff8dc, 'crimson': 0xdc143c, 'cyan': 0x00ffff, 'darkblue': 0x00008b, 'darkcyan': 0x008b8b,
    'darkgoldenrod': 0xb8860b, 'darkgray': 0xa9a9a9, 'darkgreen': 0x006400, 'darkgrey': 0xa9a9a9,
    'darkkhaki': 0xbdb76b, 'darkmagenta': 0x8b008b, 'darkolivegreen': 0x556b2f, 'darkorange': 0xff8c00,
    'darkorchid': 0x9932cc, 'darkred': 0x8b0000, 'darksalmon': 0xe9967a, 'darkseagreen': 0x8fbc8f,
    'darkslateblue': 0x483d8b, 'darkslategray': 0x2f4f4f, 'darkslategrey': 0x2f4f4f, 'darkturquoise': 0x00ced1,
    'darkviolet': 0x9400d3, 'deeppink': 0xff1493, 'deepskyblue': 0x00bfff, 'dimgray': 0x696969,
    'dimgrey': 0x696969, 'dodgerblue': 0x1e90ff, 'firebrick': 0xb22222, 'floralwhite': 0xfffaf0,
    'forestgreen': 0x228b22, 'fuchsia': 0xff00ff, 'gainsboro': 0xdcdcdc, 'ghostwhite': 0xf8f8ff, 'gold': 0xffd700,
    'goldenrod': 0xdaa520, 'gray': 0x808080, 'green': 0x008000, 'greenyellow': 0xadff2f, 'grey': 0x808080,
    'honeydew': 0xf0fff0, 'hotpink': 0xff69b4, 'indianred': 0xcd5c5c, 'indigo': 0x4b0082, 'ivory': 0xfffff0,
    'khaki': 0xf0e68c, 'lavender': 0xe6e6fa, 'lavenderblush': 0xfff0f5, 'lawngreen': 0x7cfc00,
    'lemonchiffon': 0xfffacd, 'lightblue': 0xadd8e6, 'lightcoral': 0xf08080, 'lightcyan': 0xe0ffff,
    'lightgoldenrodyellow': 0xfafad2, 'lightgray': 0xd3d3d3, 'lightgreen': 0x90ee90, 'lightgrey': 0xd3d3d3,
    'lightpink': 0xffb6c1, 'lightsalmon': 0xffa07a, 'lightseagreen': 0x20b2aa, 'lightskyblue': 0x87cefa,
    'lightslategray': 0x778899, 'lightslategrey': 0x778899, 'lightsteelblue': 0xb0c4de, 'lightyellow': 0xffffe0,
    'lime': 0x00ff00, 'limegreen': 0x32cd32, 'linen': 0xfaf0e6, 'magenta': 0xff00ff, 'maroon': 0x800000,
    'mediumaquamarine': 0x66cdaa, 'mediumblue': 0x0000cd, 'mediumorchid': 0xba55d3, 'mediumpurple': 0x9370db,
    'mediumseagreen': 0x3cb371, 'mediumslateblue': 0x7b68ee, 'mediumspringgreen': 0x00fa9a,
    'mediumturquoise': 0x48d1cc, 'mediumvioletred': 0xc71585, 'midnightblue': 0x191970, 'mintcream': 0xf5fffa,
    'mistyrose': 0xffe4e1, 'moccasin': 0xffe4b5, 'navajowhite': 0xffdead, 'navy': 0x000080, 'oldlace': 0xfdf5e6,
    'olive': 0x808000, 'olivedrab': 0x6b8e23, 'orange': 0xffa500, 'orangered': 0xff4500, 'orchid': 0xda70d6,
    'palegoldenrod': 0xeee8aa, 'palegreen': 0x98fb98, 'paleturquoise': 0xafeeee, 'palevioletred': 0xdb7093,
    'papayawhip': 0xffefd5, 'peachpuff': 0xffdab9, 'peru': 0xcd853f, 'pink': 0xffc0cb, 'plum': 0xdda0dd,
    'powderblue': 0xb0e0e6, 'purple': 0x800080, 'rebeccapurple': 0x663399, 'red': 0xff0000, 'rosybrown': 0xbc8f8f,
    'royalblue': 0x4169e1, 'saddlebrown': 0x8b4513, 'salmon': 0xfa8072, 'sandybrown': 0xf4a460,
    'seagreen': 0x2e8b57, 'seashell': 0xfff5ee, 'sienna': 0xa0522d, 'silver': 0xc0c0c0, 'skyblue': 0x87ceeb,
    'slateblue': 0x6a5acd, 'slategray': 0x708090, 'slategrey': 0x708090, 'snow': 0xfffafa, 'springgreen': 0x00ff7f,
    'steelblue': 0x4682b4, 'tan': 0xd2b48c, 'teal': 0x008080, 'thistle': 0xd8bfd8, 'tomato': 0xff6347,
    'turquoise': 0x40e0d0, 'violet': 0xee82ee, 'wheat': 0xf5deb3, 'white': 0xffffff, 'whitesmoke': 0xf5f5f5,
    'yellow': 0xffff00, 'yellowgreen': 0x9acd32
}
# Text and canvas colours before any style: black on white, links blue.
_DEFAULT_TEXT, _DEFAULT_CANVAS, _LINK_TEXT = (0, 0, 0, 1.0), (255, 255, 255), '#0000ee'
# Below this contrast ratio (1 for identical colours, 21 for black on white), text is the
# colour of its background: #fafafa or #f4f4f4 on white, #111 on black.
_SAME_COLOUR_CONTRAST = 1.1
# Below this many letters, text the colour of its background is too little to dilute the
# model (a preheader): the model reads it, and only the text rules also read without it.
_SAME_COLOUR_MODEL_LETTERS = 200
# Cascaded for text that may be the colour of its background: the text colour's value
# (beside the 'color' class), and the background's colour and image.
_COLOUR_PROPERTIES = frozenset({'text-color', 'background-color', 'background-image'})
_BACKGROUND_IMAGE = re.compile(
    r'(?:url|image|image-set|-webkit-image-set|element|cross-fade'
    r'|(?:-webkit-|-moz-|-o-)?(?:repeating-)?(?:linear|radial|conic)-gradient|-webkit-gradient)\(')


def _css_channel(text: str, scale: float) -> float:
    """A colour channel: a number, or a percentage of scale; 'none' is zero."""
    if text == 'none':
        return 0.0
    return float(text[:-1]) * scale / 100 if text.endswith('%') else float(text)


def _hue_degrees(text: str) -> float:
    match = re.fullmatch(rf'({_CSS_NUMBER})(deg|grad|rad|turn)?', text)
    if not match:
        return 0.0
    return float(match.group(1)) * {None: 1, 'deg': 1, 'grad': 0.9, 'rad': 180 / math.pi, 'turn': 360}[match.group(2)]


def _srgb_encode(linear: float) -> float:
    return 12.92 * linear if abs(linear) <= 0.0031308 else math.copysign(1.055 * abs(linear) ** (1 / 2.4) - 0.055, linear)


def _srgb_decode(channel: float) -> float:
    return channel / 12.92 if abs(channel) <= 0.04045 else math.copysign(((abs(channel) + 0.055) / 1.055) ** 2.4, channel)


def _matrix(rows, vector):
    return [sum(row[index] * vector[index] for index in range(3)) for row in rows]


# CSS Color 4: linear-light RGB spaces to XYZ, Bradford D50 to D65, and XYZ D65 to linear sRGB.
_XYZ_D65_TO_SRGB = ((3.2409699419045226, -1.537383177570094, -0.4986107602930034),
                    (-0.9692436362808796, 1.8759675015077202, 0.04155505740717559),
                    (0.05563007969699366, -0.20397695888897652, 1.0569715142428786))
_D50_TO_D65 = ((0.955473421488075, -0.02309845494876471, 0.06325924320057072),
               (-0.0283697093338637, 1.0099953980813041, 0.021041441191917323),
               (0.012314014864481998, -0.020507649298898964, 1.330365926242124))
_RGB_SPACES = {
    'display-p3': (((0.4865709486482162, 0.26566769316909306, 0.1982172852343625),
                    (0.2289745640697488, 0.6917385218365064, 0.079286914093745),
                    (0.0, 0.04511338185890264, 1.043944368900976)), _srgb_decode, False),
    'a98-rgb': (((0.5766690429101305, 0.1855582379065463, 0.1882286462349947),
                 (0.29734497525053605, 0.6273635662554661, 0.07529145849399788),
                 (0.02703136138641234, 0.07068885253582723, 0.9913375368376388)),
                lambda c: math.copysign(abs(c) ** (563 / 256), c), False),
    'prophoto-rgb': (((0.7977604896723027, 0.13518583717574031, 0.0313493495815248),
                      (0.2880711282292934, 0.7118432178101014, 0.00008565396060525902),
                      (0.0, 0.0, 0.8251046025104601)),
                     lambda c: c / 16 if abs(c) <= 16 / 512 else math.copysign(abs(c) ** 1.8, c), True),
    'rec2020': (((0.6369580483012914, 0.14461690358620832, 0.1688809751641721),
                 (0.2627002120112671, 0.6779980715188708, 0.05930171646986196),
                 (0.0, 0.028072693049087428, 1.060985057710791)),
                lambda c: c / 4.5 if abs(c) < 0.018053968510807 * 4.5
                else math.copysign(((abs(c) + 0.09929682680944) / 1.09929682680944) ** (1 / 0.45), c), False),
}
_D50_WHITE = (0.3457 / 0.3585, 1.0, (1 - 0.3457 - 0.3585) / 0.3585)


def _xyz_to_srgb(xyz, d50=False):
    """XYZ (D65, or D50) to sRGB channels 0-255, clamped to the gamut."""
    if d50:
        xyz = _matrix(_D50_TO_D65, xyz)
    return tuple(min(255.0, max(0.0, 255 * _srgb_encode(channel))) for channel in _matrix(_XYZ_D65_TO_SRGB, xyz))


def _lab_to_xyz(lightness, a, b):
    """CIE Lab (D50) to XYZ D50."""
    epsilon, kappa = 216 / 24389, 24389 / 27
    fy = (lightness + 16) / 116
    fx, fz = fy + a / 500, fy - b / 200
    xr = fx ** 3 if fx ** 3 > epsilon else (116 * fx - 16) / kappa
    yr = fy ** 3 if lightness > kappa * epsilon else lightness / kappa
    zr = fz ** 3 if fz ** 3 > epsilon else (116 * fz - 16) / kappa
    return [xr * _D50_WHITE[0], yr * _D50_WHITE[1], zr * _D50_WHITE[2]]


def _oklab_to_srgb(lightness, a, b):
    l_, m_, s_ = (lightness + 0.3963377774 * a + 0.2158037573 * b, lightness - 0.1055613458 * a - 0.0638541728 * b,
                  lightness - 0.0894841775 * a - 1.2914855480 * b)
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    linear = (4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
              -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
              -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s)
    return tuple(min(255.0, max(0.0, 255 * _srgb_encode(channel))) for channel in linear)


def _wide_gamut_rgb(function: str, channels: list[str]):
    """lab(), lch(), oklab(), oklch() and color() channels as sRGB 0-255, or None."""
    if function == 'color':
        space, values = channels[0], [_css_channel(channel, 1) for channel in channels[1:]]
        if space == 'srgb':
            return tuple(min(255.0, max(0.0, 255 * value)) for value in values)
        if space == 'srgb-linear':
            return tuple(min(255.0, max(0.0, 255 * _srgb_encode(value))) for value in values)
        if space in {'xyz', 'xyz-d65', 'xyz-d50'}:
            return _xyz_to_srgb(values, d50=space == 'xyz-d50')
        if space in _RGB_SPACES:
            matrix, decode, d50 = _RGB_SPACES[space]
            return _xyz_to_srgb(_matrix(matrix, [decode(value) for value in values]), d50=d50)
        return None
    if function in {'lab', 'lch'}:
        lightness = _css_channel(channels[0], 100)
        if function == 'lab':
            a, b = _css_channel(channels[1], 125), _css_channel(channels[2], 125)
        else:
            chroma, hue = _css_channel(channels[1], 150), math.radians(_hue_degrees(channels[2]))
            a, b = chroma * math.cos(hue), chroma * math.sin(hue)
        return _xyz_to_srgb(_lab_to_xyz(lightness, a, b), d50=True)
    lightness = _css_channel(channels[0], 1)
    if function == 'oklab':
        a, b = _css_channel(channels[1], 0.4), _css_channel(channels[2], 0.4)
    else:
        chroma, hue = _css_channel(channels[1], 0.4), math.radians(_hue_degrees(channels[2]))
        a, b = chroma * math.cos(hue), chroma * math.sin(hue)
    return _oklab_to_srgb(lightness, a, b)


@lru_cache(maxsize=4096)
def _colour_rgba(value: str):
    """A CSS colour as (red, green, blue, alpha), channels 0-255 and alpha 0-1, or None
    for colours that depend on the client (system colours). Wide-gamut colours are
    converted to sRGB and clamped. currentcolor is the caller's to resolve."""
    value = value.strip().lower()
    if value == 'transparent':
        return (0, 0, 0, 0.0)
    if value in _NAMED_COLOR_VALUES:
        rgb = _NAMED_COLOR_VALUES[value]
        return (rgb >> 16, rgb >> 8 & 255, rgb & 255, 1.0)
    if _HEX_COLOR.fullmatch(value):
        digits = value[1:]
        if len(digits) in (3, 4):
            digits = ''.join(digit * 2 for digit in digits)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16),
                int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0)
    match = _COLOR_FUNCTION.fullmatch(value)
    if not match or _color_function_alpha(match.group(1), match.group(2).strip()) is None:
        return None
    function, arguments = match.group(1), match.group(2).strip()
    if ',' in arguments:
        parts = [part.strip() for part in arguments.split(',')]
        channels, alpha = parts[:3], parts[3] if len(parts) == 4 else '1'
    else:
        before, slash, after = arguments.partition('/')
        channels, alpha = before.split(), after.strip() if slash else '1'
    alpha = min(1.0, max(0.0, _css_channel(alpha, 1)))
    if function in {'lab', 'lch', 'oklab', 'oklch', 'color'}:
        rgb = _wide_gamut_rgb(function, channels)
        return None if rgb is None else (*(round(channel) for channel in rgb), alpha)
    if function.startswith('rgb'):
        red, green, blue = (min(255.0, max(0.0, _css_channel(channel, 255))) for channel in channels)
    else:
        hue = _hue_degrees(channels[0]) % 360
        first, second = (min(1.0, max(0.0, _css_channel(channel, 100) / 100)) for channel in channels[1:])
        if function == 'hwb' and first + second >= 1:
            red = green = blue = 255 * first / (first + second)
        else:
            saturation, lightness = (1.0, 0.5) if function == 'hwb' else (first, second)

            def component(offset):
                k = (offset + hue / 30) % 12
                return lightness - saturation * min(lightness, 1 - lightness) * max(-1, min(k - 3, 9 - k, 1))
            red, green, blue = (255 * component(offset) for offset in (0, 8, 4))
            if function == 'hwb':
                red, green, blue = (channel * (1 - first - second) + 255 * first for channel in (red, green, blue))
    return (round(red), round(green), round(blue), alpha)


def _legacy_colour(value: str):
    """An HTML colour attribute (bgcolor, font color, body text) as browsers parse it:
    a named colour, #rgb, or the legacy hex digits (bgcolor="ffffff"; "fff" is #0f0f0f).
    Returns '#rrggbb', or None where browsers ignore it."""
    value = value.strip()
    if not value or value.lower() == 'transparent':
        return None
    if value.lower() in _NAMED_COLOR_VALUES:
        return f'#{_NAMED_COLOR_VALUES[value.lower()]:06x}'
    if re.fullmatch('#[0-9a-fA-F]{3}', value):
        return '#' + ''.join(digit * 2 for digit in value[1:].lower())
    value = re.sub('[\U00010000-\U0010ffff]', '00', value)[:128]
    value = re.sub('[^0-9a-fA-F]', '0', value[1:] if value.startswith('#') else value)
    while not value or len(value) % 3:
        value += '0'
    length = len(value) // 3
    parts = [value[index * length:(index + 1) * length] for index in range(3)]
    if length > 8:
        parts, length = [part[-8:] for part in parts], 8
    while length > 2 and all(part[0] == '0' for part in parts):
        parts, length = [part[1:] for part in parts], length - 1
    return '#' + ''.join(f'{int(part[:2], 16):02x}' for part in parts)


# The components of a background layer. Each may appear once (a repeat may take two
# words, a box two), and its position and size follow CSS's grammar: browsers drop a
# declaration that breaks it ("left left black", "repeat repeat repeat black").
_BACKGROUND_REPEATS = frozenset({'repeat', 'space', 'round', 'no-repeat'})
_BACKGROUND_ATTACHMENTS = frozenset({'scroll', 'fixed', 'local'})
_BACKGROUND_BOXES = frozenset({'border-box', 'padding-box', 'content-box', 'text'})
_BACKGROUND_POSITION_AXES = {'left': 'h', 'right': 'h', 'top': 'v', 'bottom': 'v', 'center': 'c'}
# A url() as CSS tokenizes it: an unquoted address with no whitespace, quote, bracket,
# control character or lone backslash inside, or one quoted string, either with optional
# whitespace around. Anything else (url(a"b"), url(a(b)), two strings, or a comma between
# them) is a bad URL, and the declaration holding it is dropped.
_CSS_URL = re.compile(
    r"""url\(\s*(?:"(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*'"""
    r"""|(?:[^\s"'()\\\x00-\x08\x0b\x0e-\x1f\x7f]|\\[^\n])*)\s*\)""")
# Substitution functions: browsers accept a declaration holding one when they parse it,
# and decide when they substitute it (var(), env(safe-area-inset-top), attr(), if()).
_CSS_SUBSTITUTION = re.compile(r'(?<![\w-])(?:var|env|attr|if|inherit)\(', re.IGNORECASE)
# A math function (CSS Values 4): its result's type decides where it is valid.
_CSS_MATH_FUNCTIONS = frozenset('''calc min max clamp round mod rem abs sign sin cos tan asin acos atan atan2 pow sqrt
    hypot log exp'''.split())
_CSS_MATH = re.compile(rf"(?:-webkit-calc|{'|'.join(sorted(_CSS_MATH_FUNCTIONS, key=len, reverse=True))})\(.*\)\Z", re.S)
_CSS_MATH_TOKEN = re.compile(rf'(\s+)|({_CSS_NUMBER})(%|[a-z]+)?|(-?[a-z][a-z0-9-]*)(\()?|([-+*/(),])')
_CSS_MATH_CONSTANTS = frozenset({'e', 'pi', 'infinity', '-infinity', 'nan'})
_CSS_OTHER_UNITS = {'s': 'time', 'ms': 'time', 'hz': 'frequency', 'khz': 'frequency', 'dpi': 'resolution',
                    'dpcm': 'resolution', 'dppx': 'resolution', 'x': 'resolution'}
# CSS units by what they measure.
_CSS_LENGTH_UNITS = frozenset("""px em rem ex rex ch rch ic ric cap rcap lh rlh vw vh vi vb vmin vmax svw svh svi svb
    svmin svmax lvw lvh lvi lvb lvmin lvmax dvw dvh dvi dvb dvmin dvmax cqw cqh cqi cqb cqmin cqmax cm mm q in pt pc""".split())
_CSS_ANGLE_UNITS = frozenset({'deg', 'grad', 'rad', 'turn'})
# A gradient's first argument (CSS Images 4): a linear gradient's angle or "to" sides, a
# radial one's shape, size and "at" position, a conic one's "from" angle and "at"
# position; any of them may add the colour space it interpolates in ("in oklch longer hue").
_GRADIENT_SIDES = {'left': 'h', 'right': 'h', 'top': 'v', 'bottom': 'v'}
_GRADIENT_EXTENTS = frozenset({'closest-side', 'closest-corner', 'farthest-side', 'farthest-corner'})
_GRADIENT_RECTANGULAR_SPACES = frozenset("""srgb srgb-linear display-p3 a98-rgb prophoto-rgb rec2020 lab oklab xyz xyz-d50
    xyz-d65""".split())
_GRADIENT_POLAR_SPACES = frozenset({'hsl', 'hwb', 'lch', 'oklch'})
_GRADIENT_HUE_METHODS = frozenset({'shorter', 'longer', 'increasing', 'decreasing'})


def _css_top_level(value: str, separators: str) -> list[str]:
    """value split at the given characters outside parentheses and quotes."""
    parts, current, depth, quote = [], [], 0, None
    for character in value:
        if quote:
            quote = None if character == quote else quote
        elif character in "\"'":
            quote = character
        elif character == '(':
            depth += 1
        elif character == ')':
            depth -= 1
        elif depth == 0 and character in separators:
            parts.append(''.join(current))
            current = []
            continue
        current.append(character)
    parts.append(''.join(current))
    return parts


def _css_words(value: str) -> list[str]:
    """Space-separated words; a function's closing bracket also ends a word, as CSS
    tokenizes it ("calc(1px)calc(2px)" is two values, "url(a.png)no-repeat" two)."""
    words = []
    for word in _css_top_level(value, ' \t\n\r\f'):
        depth, start = 0, 0
        for index, character in enumerate(word):
            depth += {'(': 1, ')': -1}.get(character, 0)
            if character == ')' and depth == 0 and index + 1 < len(word):
                words.append(word[start:index + 1])
                start = index + 1
        words.append(word[start:])
    return [word for word in words if word]


class _MathTooDeep(Exception):
    """A math expression nested past _CSS_MATH_DEPTH."""


# Math nested deeper than this is left untyped (unknown) rather than parsed further.
_CSS_MATH_DEPTH = 32
_MATH_NONE, _MATH_UNKNOWN = 'none', 'unknown'


def _css_math_powers(first, second, sign=1):
    powers = dict(first)
    for base, exponent in second:
        powers[base] = powers.get(base, 0) + sign * exponent
    return tuple(sorted((base, exponent) for base, exponent in powers.items() if exponent))


def _css_math_sum(types):
    """The type of a sum (or of min(), max() and the like) of typed values, as CSS Values 4
    adds types: equal powers, or a percentage folded into the other side's length or angle,
    which becomes its basis (1px + 10% is a length); None where they cannot be added. A
    percentage has no basis among times or other units here (1s + 1%), nor two bases."""
    if _MATH_UNKNOWN in types:
        return _MATH_UNKNOWN
    if _MATH_NONE in types:
        return None
    powers, percent, basis = types[0]
    for other, other_percent, other_basis in types[1:]:
        percent = percent or other_percent
        if basis and other_basis and basis != other_basis:
            return None
        basis = basis or other_basis
        if other == powers:
            continue
        present = {base for base, _exponent in powers + other}
        for base in sorted(({basis} if basis else {'length', 'angle'}) & present):
            folded = [_css_math_percent_as(side, base) for side in (powers, other)]
            if folded[0] == folded[1]:
                powers, basis = folded[0], base
                break
        else:
            return None
    return powers, percent, basis


def _css_math_percent_as(powers, base):
    """The powers with a percentage read as the base it resolves against."""
    return _css_math_powers((), tuple((base if name == 'percent' else name, exponent) for name, exponent in powers))


def _css_math_type(word: str) -> str | None:
    """The type of a math function's result: 'number', 'percentage', 'length', 'angle',
    'length-percentage' or 'angle-percentage' (a percentage resolved against the other
    side), or another dimension; 'unknown' where this reader cannot tell (var(), functions
    it does not model, nesting past _CSS_MATH_DEPTH); None where every browser rejects it
    (calc(banana), calc(1px + 1deg), calc(1px+1px), atan2(1deg, 1%)).

    Types multiply and divide by their powers (calc(1px * 1px / 1px) is a length), and a
    percentage anywhere is remembered: where the value takes no percentage, any is invalid."""
    tokens, index = [], 0
    while index < len(word):
        match = _CSS_MATH_TOKEN.match(word, index)
        if not match:
            return None
        index = match.end()
        if match.group(1):
            if tokens:
                tokens[-1] = (*tokens[-1][:2], True, tokens[-1][3])
            continue
        spaced = not tokens or tokens[-1][2]
        if match.group(2) is not None:
            unit = match.group(3)
            kind = (() if unit is None else (('percent', 1),) if unit == '%' else (('length', 1),)
                    if unit in _CSS_LENGTH_UNITS else (('angle', 1),) if unit in _CSS_ANGLE_UNITS
                    else ((_CSS_OTHER_UNITS[unit], 1),) if unit in _CSS_OTHER_UNITS else None)
            if kind is None:
                return None
            tokens.append(('value', (kind, unit == '%', None), False, spaced))
        elif match.group(4) is not None:
            tokens.append(('function' if match.group(5) else 'name', match.group(4), False, spaced))
        else:
            tokens.append(('operator', match.group(6), False, spaced))
    position, depth = [0], [0]

    def peek():
        return tokens[position[0]] if position[0] < len(tokens) else (None, None, False, False)

    def take():
        token = peek()
        position[0] += 1
        return token

    def close():
        if take()[:2] != ('operator', ')'):
            raise ValueError
        depth[0] -= 1

    def opened():
        depth[0] += 1
        if depth[0] > _CSS_MATH_DEPTH:
            raise _MathTooDeep

    def arguments():
        values = [total()]
        while peek()[:2] == ('operator', ','):
            take()
            values.append(total())
        close()
        return values

    def atom():
        kind, value, _after, _before = take()
        if kind == 'value':
            return value
        if kind == 'name':
            if value in _CSS_MATH_CONSTANTS:
                return (), False, None
            if value == 'none':
                return _MATH_NONE  # only clamp() takes it, as a missing bound
            raise ValueError
        if (kind, value) == ('operator', '('):
            opened()
            result = total()
            close()
            # Only a bare none is a missing bound: clamp((none), …) is invalid.
            return None if result == _MATH_NONE else result
        if kind != 'function':
            raise ValueError
        opened()
        if value not in _CSS_MATH_FUNCTIONS:
            # var(), env() or a function this reader does not model: skip to its end.
            level = 1
            while level:
                token = take()
                if token[0] is None:
                    raise ValueError
                level += {'(': 1, ')': -1}.get(token[1], 0) if token[0] == 'operator' else token[0] == 'function'
            depth[0] -= 1
            return _MATH_UNKNOWN
        if value == 'round' and peek()[0] == 'name' and peek()[1] in {'nearest', 'up', 'down', 'to-zero'}:
            take()
            if take()[:2] != ('operator', ','):
                raise ValueError
        values = arguments()
        counts = {'calc': (1, 1), 'clamp': (3, 3), 'round': (1, 2), 'mod': (2, 2), 'rem': (2, 2), 'abs': (1, 1),
                  'sign': (1, 1), 'atan2': (2, 2), 'pow': (2, 2), 'log': (1, 2)}.get(value, (1, 1) if value in {
                      'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sqrt', 'exp'} else (1, 32))
        if not counts[0] <= len(values) <= counts[1] or None in values:
            raise ValueError
        if value == 'clamp':
            # clamp(none, 10px, none): either bound may be missing, never the value.
            if values[1] == _MATH_NONE:
                return None
            values = [value_type for value_type in values if value_type != _MATH_NONE]
        elif _MATH_NONE in values:
            return None
        if _MATH_UNKNOWN in values:
            return _MATH_UNKNOWN
        percent = any(value_type[1] for value_type in values)
        bases = {value_type[2] for value_type in values} - {None}
        if len(bases) > 1:
            return None
        basis = next(iter(bases), None)
        # Where a percentage takes part, a mismatch may still resolve in the browser: unknown.
        mismatch = _MATH_UNKNOWN if percent else None
        if value in {'sin', 'cos', 'tan'}:
            return ((), percent, basis) if values[0][0] in {(), (('angle', 1),)} else mismatch
        if value in {'asin', 'acos', 'atan'}:
            return ((('angle', 1),), percent, basis) if values[0][0] == () else mismatch
        if value in {'pow', 'sqrt', 'exp', 'log'}:
            # Browsers accept some dimensions here (sqrt(1vw)): only numbers are typed.
            return ((), percent, basis) if all(value_type[0] == () for value_type in values) else _MATH_UNKNOWN
        if value == 'round' and len(values) == 1 and values[0][0] != ():
            return None  # round(1px) needs its interval; round(1.5) does not
        result = _css_math_sum(values)
        if value == 'atan2':
            # Browsers reject an angle or length mixed with a percentage in atan2();
            # two percentages resolve against the place's basis, where it has one.
            if result is None or percent and any(value_type[0] != (('percent', 1),) for value_type in values):
                return None
            return (('angle', 1),), percent, None
        if value == 'sign':
            return None if result is None else ((), percent, result[2])
        return result

    def product():
        result = atom()
        while peek()[:2] in {('operator', '*'), ('operator', '/')}:
            operator = take()[1]
            other = atom()
            if None in (result, other) or _MATH_NONE in (result, other):
                return None
            if _MATH_UNKNOWN in (result, other):
                result = _MATH_UNKNOWN
            elif result[2] and other[2] and result[2] != other[2]:
                return None  # a percentage cannot resolve against a length and an angle at once
            else:
                result = (_css_math_powers(result[0], other[0], 1 if operator == '*' else -1), result[1] or other[1],
                          result[2] or other[2])
        return result

    def total():
        result = product()
        while peek()[:2] in {('operator', '+'), ('operator', '-')}:
            operator = take()
            # "+" and "-" need whitespace on both sides: calc(1px+1px) is invalid.
            if not operator[3] or not operator[2]:
                raise ValueError
            other = product()
            if None in (result, other):
                return None
            result = _css_math_sum([result, other])
            if result is None:
                return None
        return result

    try:
        result = atom()
    except (ValueError, IndexError):
        return None
    except (_MathTooDeep, RecursionError):
        return _MATH_UNKNOWN
    if position[0] != len(tokens) or result is None or result == _MATH_NONE:
        return None
    if result == _MATH_UNKNOWN:
        return result
    powers, percent, basis = result
    if basis:
        # Resolved against a length or an angle: what is left must be that, the percentages
        # products kept included.
        return f'{basis}-percentage' if _css_math_percent_as(powers, basis) == ((basis, 1),) else None
    if powers == (('percent', 1),):
        return 'percentage'
    if any(base == 'percent' for base, _exponent in powers):
        # A percentage resolves against the place's basis, a length or an angle, also in
        # products (10em / 1% * 1vw is a length).
        for base in ('length', 'angle'):
            if _css_math_percent_as(powers, base) == ((base, 1),):
                return f'{base}-percentage'
        return None
    if not powers:
        return 'number'
    if len(powers) == 1 and powers[0][1] == 1:
        base = powers[0][0]
        return f'{base}-percentage' if percent and base in {'length', 'angle'} else base
    return None


def _css_quantity(word: str) -> str | None:
    """What a value measures: 'length', 'angle', 'percentage', 'zero' (a unitless 0),
    'number' (another unitless number), 'length-percentage' or 'angle-percentage' (from a
    math function), 'math-unknown' (a math function whose type is unknown), or None."""
    if _CSS_MATH.match(word):
        kind = _css_math_type(word)
        return 'math-unknown' if kind == 'unknown' else kind
    match = _CSS_DIMENSION.fullmatch(word)
    if not match:
        return None
    unit = match.group(2)
    if unit is None:
        return 'zero' if float(match.group(1)) == 0 else 'number'
    return ('percentage' if unit == '%' else 'length' if unit in _CSS_LENGTH_UNITS
            else 'angle' if unit in _CSS_ANGLE_UNITS else None)


def _css_length(word: str) -> bool:
    """A length or percentage, as a background position or size takes it: a unitless
    number other than 0 is none, even in a quirks-mode document."""
    return _css_quantity(word) in _CSS_LENGTH_PERCENTAGE


# The types each place takes; a math function of unknown type is accepted, and leaves a
# gradient's colours unknown.
_CSS_LENGTH_PERCENTAGE = frozenset({'length', 'percentage', 'zero', 'length-percentage', 'math-unknown'})
# Angles and percentages mixed in one conic stop (calc(10% + 1deg)): Chromium 154 accepts
# them, 148 does not, so the gradient's colours are left unknown.
_CSS_ANGLE_PERCENTAGE = frozenset({'angle', 'percentage', 'zero', 'angle-percentage', 'math-unknown'})
_CSS_ANGLE = frozenset({'angle', 'zero', 'math-unknown'})


def _gradient_setup_valid(kind: str, words: list[str]) -> bool:
    """Whether a gradient's first argument is valid for its kind."""
    if 'in' in words:
        at = words.index('in')
        space = words[at + 1] if at + 1 < len(words) else ''
        clause = 2
        if space in _GRADIENT_POLAR_SPACES and words[at + 2:at + 4][1:] == ['hue'] \
                and words[at + 2] in _GRADIENT_HUE_METHODS:
            clause = 4
        elif space not in _GRADIENT_RECTANGULAR_SPACES | _GRADIENT_POLAR_SPACES:
            return False
        # The interpolation clause stands at the start or the end.
        if at not in (0, len(words) - clause):
            return False
        words = words[:at] + words[at + clause:]
    if kind == 'linear':
        if len(words) == 1:
            return _css_quantity(words[0]) in _CSS_ANGLE
        if words[:1] == ['to'] and 2 <= len(words) <= 3:
            axes = [_GRADIENT_SIDES.get(word) for word in words[1:]]
            return None not in axes and len(set(axes)) == len(axes)
        return not words
    position = []
    if 'at' in words:
        at = words.index('at')
        words, position = words[:at], words[at + 1:]
        if not all(word in _BACKGROUND_POSITION_AXES or _css_length(word) for word in position) \
                or not _background_position_valid(position):
            return False
    if kind == 'conic':
        if not words:
            return True
        return len(words) == 2 and words[0] == 'from' and _css_quantity(words[1]) in _CSS_ANGLE
    shapes = [word for word in words if word in {'circle', 'ellipse'}]
    extents = [word for word in words if word in _GRADIENT_EXTENTS]
    sizes = [word for word in words if word not in {'circle', 'ellipse'} and word not in _GRADIENT_EXTENTS]
    if len(shapes) > 1 or len(extents) > 1 or (extents and sizes) or len(sizes) > 2:
        return False
    if any(_css_quantity(word) not in _CSS_LENGTH_PERCENTAGE or word.startswith('-') for word in sizes):
        return False
    # One size is a circle's radius (no percentage); two are an ellipse's.
    if len(sizes) == 1 and ('ellipse' in shapes or _css_quantity(sizes[0]) in {'percentage', 'length-percentage'}):
        return False
    return not (len(sizes) == 2 and 'circle' in shapes)


def _gradient_stops(image: str):
    """A standard gradient's stop colours, with None for each stop whose colour this
    reader cannot compute (color-mix(), a system colour, currentcolor); [] for a gradient
    browsers reject, which drops its declaration; None for any other image. Linear and
    radial stops sit at lengths or percentages, conic ones at angles or percentages; a
    colour hint (a position alone) stands between two stops."""
    match = re.fullmatch(r'(?:repeating-)?(linear|radial|conic)-gradient\((.*)\)', image, re.S)
    if not match:
        return None
    kind = match.group(1)
    positions = _CSS_ANGLE_PERCENTAGE if kind == 'conic' else _CSS_LENGTH_PERCENTAGE
    arguments = [_css_words(argument) for argument in _css_top_level(match.group(2), ',')]
    items = []
    for index, words in enumerate(arguments):
        colours = [word for word in words if word not in _CSS_WIDE_KEYWORDS and not _CSS_MATH.match(word) and (
            word == 'currentcolor' or _color_class(word) in {'visible', 'transparent', 'unresolved'})]
        rest = [word for word in words if word not in colours]
        # A stop's colour comes first, its positions after it.
        if len(colours) == 1 and words[0] == colours[0]:
            if len(rest) > 2 or any(_css_quantity(word) not in positions for word in rest):
                return []
            colour = colours[0]
            items.append(colour if _color_class(colour) in {'visible', 'transparent'} and _colour_rgba(colour) else None)
        elif not colours and len(words) == 1 and _css_quantity(words[0]) in positions and index:
            items.append('#hint')
        elif not index and words and not colours and _gradient_setup_valid(kind, words):
            continue
        else:
            return []
    # A hint needs a stop on each side.
    for at, item in enumerate(items):
        if item == '#hint' and (at == 0 or at == len(items) - 1 or '#hint' in (items[at - 1], items[at + 1])):
            return []
    stops = [item for item in items if item != '#hint']
    # A math function this reader cannot type may still be invalid: the colours are unknown.
    unknown = {'math-unknown', 'angle-percentage'} if kind == 'conic' else {'math-unknown'}
    if any(_css_quantity(word) in unknown for words in arguments for word in words):
        stops.append(None)
    return stops


def _background_position_valid(words: list[str]) -> bool:
    """One to four words of a background position, as CSS accepts them."""
    kinds = [_BACKGROUND_POSITION_AXES.get(word, 'l') for word in words]
    if len(kinds) <= 1:
        return len(kinds) == 1
    if len(kinds) == 2:
        if 'l' in kinds:
            return kinds[0] in 'hcl' and kinds[1] in 'vcl'
        return kinds[0] != kinds[1] or kinds[0] == 'c'
    groups, index = [], 0
    while index < len(kinds):
        offset = index + 1 < len(kinds) and kinds[index + 1] == 'l'
        if kinds[index] == 'l' or (offset and kinds[index] == 'c'):
            return False
        groups.append(kinds[index])
        index += 2 if offset else 1
    return len(kinds) <= 4 and len(groups) == 2 and (groups[0] != groups[1] or groups[0] == 'c')


@lru_cache(maxsize=4096)
def _background_valid(value: str, name: str = 'background') -> bool:
    """Whether a background shorthand (or background-image) is valid CSS as far as this
    reader can tell: each layer holds one image at most, a position and size, a repeat,
    an attachment and boxes, each once, and only the shorthand's last layer one colour.
    Browsers drop an invalid declaration whole ("background: banana black" leaves the
    background as it was), and so a gradient browsers reject. A var() or env() is decided
    where it is substituted."""
    value = value.strip()
    if _CSS_SUBSTITUTION.search(value) or value in _CSS_WIDE_KEYWORDS:
        return bool(value)
    layers = _css_top_level(value, ',')
    for index, layer in enumerate(layers):
        pieces = _css_top_level(layer, '/')
        if len(pieces) > 2:
            return False
        words, size = _css_words(pieces[0]), None
        if len(pieces) == 2:
            # The size directly follows the position's '/'; other components may follow it.
            after = _css_words(pieces[1])
            size = after[:1] if after[:1] in (['cover'], ['contain']) else list(
                takewhile(lambda word: word == 'auto' or _css_length(word), after[:2]))
            # A size is never negative (a position may be).
            if not size or any(word.startswith('-') for word in size):
                return False
            ends = len(words)
            words += after[len(size):]
        if not words:
            return False
        counts = {'image': 0, 'repeat': 0, 'attachment': 0, 'box': 0, 'colour': 0}
        position = []
        for at, word in enumerate(words):
            if word == 'none' or (_BACKGROUND_IMAGE.match(word) and word.endswith(')')):
                if _gradient_stops(word) == [] or word.startswith('url(') and not _CSS_URL.fullmatch(word):
                    return False
                counts['image'] += 1
            elif word in {'repeat-x', 'repeat-y'}:
                counts['repeat'] += 2
            elif word in _BACKGROUND_REPEATS:
                counts['repeat'] += 1
            elif word in _BACKGROUND_ATTACHMENTS:
                counts['attachment'] += 1
            elif word in _BACKGROUND_BOXES:
                # Two boxes are the origin and the clip; only the clip may be the text.
                counts['box'] += 1 if word != 'text' or 'text' not in words[:at] else 2
            elif word in _BACKGROUND_POSITION_AXES or _css_length(word):
                position.append(at)
            elif (index == len(layers) - 1 and word not in _CSS_WIDE_KEYWORDS
                  and (word == 'currentcolor' or _color_class(word) in {'visible', 'transparent', 'unresolved'})):
                counts['colour'] += 1
            else:
                return False
        if name == 'background-image':
            if counts['image'] != 1 or len(words) != 1 or size is not None:
                return False
            continue
        if (counts['image'] > 1 or counts['repeat'] > 2 or counts['attachment'] > 1 or counts['box'] > 2
                or counts['colour'] > 1):
            return False
        # The position's words stand together, and a size follows it directly.
        if position and (position != list(range(position[0], position[-1] + 1))
                         or not _background_position_valid([words[at] for at in position])):
            return False
        if size is not None and (not position or position[-1] != ends - 1):
            return False
    return True


@lru_cache(maxsize=4096)
def _background_clip_valid(value: str) -> bool:
    """Whether a background-clip value is valid: one box for each layer."""
    return bool(_CSS_SUBSTITUTION.search(value)) or value in _CSS_WIDE_KEYWORDS or all(
        len(words) == 1 and words[0] in _BACKGROUND_BOXES
        for words in map(_css_words, _css_top_level(value, ',')))


# Background properties cascaded with the colours, besides the colour and image: the
# clip, and the size and repeat that decide whether a gradient covers the box.
_BACKGROUND_LAYOUT_PROPERTIES = ('background-clip', 'background-size', 'background-repeat')
_BACKGROUND_PARTIAL_REPEATS = frozenset({'no-repeat', 'repeat-x', 'repeat-y', 'space'})


def _background_tiling_valid(name: str, value: str) -> bool:
    """Whether a background-size or background-repeat value is valid, layer by layer."""
    if _CSS_SUBSTITUTION.search(value) or value in _CSS_WIDE_KEYWORDS:
        return True
    for words in map(_css_words, _css_top_level(value, ',')):
        if name == 'background-repeat':
            if not (words in (['repeat-x'], ['repeat-y'])
                    or 1 <= len(words) <= 2 and all(word in _BACKGROUND_REPEATS for word in words)):
                return False
        elif not (words in (['cover'], ['contain']) or 1 <= len(words) <= 2 and all(
                word == 'auto' or (_css_length(word) and not word.startswith('-')) for word in words)):
            return False
    return True


def _background_tile_covers(repeat: list[str], size: list[str]) -> bool:
    """Whether a layer's image, repeated as given, covers the whole box: tiled on both axes
    (round scales the tiles to fit), at a size that is certainly above zero."""
    if _BACKGROUND_PARTIAL_REPEATS.intersection(repeat):
        return False
    for word in size:
        if word in {'auto', 'cover', 'contain'}:
            continue
        number = re.match(_CSS_NUMBER, word)
        if not (_css_quantity(word) in {'length', 'percentage'} and number and float(number.group(0)) > 0):
            return False
    return True


@lru_cache(maxsize=4096)
def _background_covers(image: str, size: str | None = None, repeat: str | None = None) -> bool:
    """Whether every layer of a background covers the box. The size and repeat come from
    the shorthand (image) unless longhands that outrank it set them."""
    if _CSS_SUBSTITUTION.search(image) or any(value is not None and (
            _CSS_SUBSTITUTION.search(value) or value in _CSS_WIDE_KEYWORDS - {'initial'}) for value in (size, repeat)):
        return False
    shorthand = []
    for layer in _css_top_level(image, ','):
        pieces = _css_top_level(layer, '/')
        words = _css_words(pieces[0])
        after = _css_words(pieces[1]) if len(pieces) > 1 else []
        layer_size = after[:1] if after[:1] in (['cover'], ['contain']) else list(
            takewhile(lambda word: word == 'auto' or _css_length(word), after[:2]))
        shorthand.append(([word for word in words + after[len(layer_size):]
                           if word in _BACKGROUND_REPEATS or word in {'repeat-x', 'repeat-y'}], layer_size))
    sizes = ([size_words for _repeat, size_words in shorthand] if size in (None, image) else
             [[] if size == 'initial' else _css_words(layer) for layer in _css_top_level(size, ',')])
    repeats = ([repeat_words for repeat_words, _size in shorthand] if repeat in (None, image) else
               [[] if repeat == 'initial' else _css_words(layer) for layer in _css_top_level(repeat, ',')])
    return all(_background_tile_covers(repeat_words, size_words) for repeat_words in repeats for size_words in sizes)


@lru_cache(maxsize=4096)
def _background_clip(value: str) -> str:
    """Which layers of a background-clip value, or of a background shorthand, clip to the
    text: 'all', 'some' or 'none'; 'unknown' where it is inherited or from var()."""
    if _CSS_SUBSTITUTION.search(value) or value == 'inherit':
        return 'unknown'
    layers = [_css_words(layer) for layer in _css_top_level(value, ',')]
    clipped = sum('text' in words for words in layers)
    return 'all' if clipped == len(layers) else 'some' if clipped else 'none'


@lru_cache(maxsize=4096)
def _background_uncertain(value: str) -> bool:
    """Whether browsers may keep or drop a background value, as far as this reader can
    tell: it holds a substitution function, a math function this reader cannot type, a
    colour it cannot compute (as a stop too), a stop browsers disagree on (an angle mixed
    with a percentage in a conic stop), or an image function whose arguments it does not
    check (-moz-linear-gradient(), image-set()). Its own colours and the background it
    would replace are then both possible."""
    if _CSS_SUBSTITUTION.search(value):
        return True
    for layer in _css_top_level(value, ','):
        for piece in _css_top_level(layer, '/'):
            for word in _css_words(piece):
                if _css_quantity(word) == 'math-unknown' or _color_class(word) == 'unresolved':
                    return True
                if not _BACKGROUND_IMAGE.match(word) or word.startswith('url('):
                    continue
                stops = _gradient_stops(word)
                if stops is None or None in stops:
                    return True
                gradient = re.fullmatch(r'(?:repeating-)?(linear|radial|conic)-gradient\((.*)\)', word, re.S)
                if gradient.group(1) == 'conic' and any(
                        _css_quantity(inner) == 'angle-percentage'
                        for argument in _css_top_level(gradient.group(2), ',') for inner in _css_words(argument)):
                    return True
    return False


@lru_cache(maxsize=4096)
def _background_parts(value: str):
    """The colour token of a background or background-color value (its last layer), or
    None; whether it paints an image; and the colour of gradients whose every stop is one
    opaque colour (linear-gradient(white, white)), which paint like that colour. A math
    function this reader cannot type anywhere in it may make the declaration invalid:
    its colours are then unknown."""
    layers = _css_top_level(value, ',')
    if _background_uncertain(value):
        return None, True, None
    images = [token for layer in layers for token in _css_words(layer) if _BACKGROUND_IMAGE.match(token)]
    colour = None
    for token in _css_words(layers[-1]):
        if token == 'currentcolor' or (token not in _CSS_WIDE_KEYWORDS
                                       and _color_class(token) in {'visible', 'transparent'}):
            colour = token
    stops = [stop for image in images for stop in (_gradient_stops(image) or [None])]
    paints = [_colour_rgba(stop) if stop else None for stop in stops]
    solid = stops[0] if images and all(paint and paint[3] >= 1 and _same_colour(paint, paints[0][:3])
                                       for paint in paints) else None
    return colour, bool(images) and solid is None, solid


def _luminance(rgb) -> float:
    def linear(channel):
        channel /= 255
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
    return 0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2])


def _blend(colour, backdrop):
    alpha = colour[3]
    return tuple(alpha * top + (1 - alpha) * bottom for top, bottom in zip(colour[:3], backdrop))


def _colour_hints(tag: str, attributes: dict) -> dict:
    """Colours an element's attributes give it (bgcolor, background, <font color>, <body
    text>), and the browser's link colour, as declarations below any author rule. A VML
    shape counts as a background image: its fill is not read."""
    hints = {}
    if ':' in tag:
        # Outlook's VML shapes (v:roundrect fillcolor) paint behind their text.
        hints['background-image'] = 'url()'
    if tag in {'body', 'table', 'tr', 'td', 'th'} and attributes.get('bgcolor'):
        hints['background-color'] = _legacy_colour(attributes['bgcolor'])
    if tag in {'body', 'table', 'td', 'th'} and (attributes.get('background') or '').strip():
        hints['background-image'] = 'url()'
    if tag == 'font' and attributes.get('color'):
        hints['text-color'] = _legacy_colour(attributes['color'])
    elif tag == 'body' and attributes.get('text'):
        hints['text-color'] = _legacy_colour(attributes['text'])
    elif tag == 'a' and 'href' in attributes:
        hints['text-color'] = _LINK_TEXT
    return {name: value for name, value in hints.items() if value}


def _stylesheet_colours(css: str) -> tuple[set, set]:
    """The text colours and backgrounds a stylesheet's rules declare."""
    cleaned, _complete = _strip_css_comments(css)
    text_colours, backgrounds = set(), set()
    for block in re.findall(r'\{([^{}]*)\}', cleaned):
        if re.search(r'color|background', block, re.IGNORECASE):
            values = _style_values(block)
            text_colours.update(values[name][0] for name in ('color',) if name in values)
            backgrounds.update(values[name][0] for name in ('background-color', 'background-image', 'background-clip')
                               if name in values)
    return text_colours, backgrounds


def _colours_may_match(text_colours: set, backgrounds: set) -> bool:
    """Whether some text colour may be the colour of some background or of the canvas:
    black or link text included. A colour from var(), currentcolor or a translucent
    background may be any. A background clipped to the text decides whether transparent
    text shows."""
    texts, fills = {_DEFAULT_TEXT, _colour_rgba(_LINK_TEXT)}, {_DEFAULT_CANVAS}
    for value in text_colours:
        if 'var(' in value:
            return True
        texts.add(_colour_rgba(value) if value not in _CSS_WIDE_KEYWORDS | {'currentcolor'} else None)
    for value in backgrounds:
        token, _image, solid = _background_parts(value)
        if 'var(' in value or token == 'currentcolor' or _background_clip(value) in {'all', 'some'}:
            return True
        for paint in (_colour_rgba(token) if token else None, _colour_rgba(solid) if solid else None):
            if paint and 0 < paint[3] < 1:
                return True  # a translucent background takes the colour of what is behind it
            if paint and paint[3] > 0:
                fills.add(paint[:3])
    return any(_same_colour(text, fill) for text in texts if text for fill in fills)


@lru_cache(maxsize=4096)
def _same_colour(colour, backdrop) -> bool:
    """Whether text of colour (r, g, b, alpha) is indistinguishable from its backdrop (r, g, b)."""
    if colour is None or backdrop is None:
        return False
    lighter, darker = sorted((_luminance(_blend(colour, backdrop)), _luminance(backdrop)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05) < _SAME_COLOUR_CONTRAST


# Font sizes: absolute units restore text inside a zero-size wrapper (the inline-block
# spacing technique in HTML mail layouts); units of the parent's size keep it zero.
# Line-height and container units depend on layout the parser does not model.
_ABSOLUTE_UNITS = frozenset('px cm mm q in pt pc rem rex rch rcap ric vw vh vi vb vmin vmax '
                            'svw svh svi svb svmin svmax lvw lvh lvi lvb lvmin lvmax '
                            'dvw dvh dvi dvb dvmin dvmax'.split())
_PARENT_UNITS = frozenset('em ex ch cap ic %'.split())
_LAYOUT_UNITS = frozenset('lh rlh cqw cqh cqi cqb cqmin cqmax'.split())
_ABSOLUTE_SIZE_KEYWORDS = frozenset('xx-small x-small small medium large x-large xx-large xxx-large initial'.split())
_CSS_DIMENSION = re.compile(rf'({_CSS_NUMBER})([a-z]+|%)?')


def _length_class(value: str) -> str:
    """'zero', 'absolute', 'relative' (to the parent), 'unknown' or 'bad' for one length."""
    match = _CSS_DIMENSION.fullmatch(value)
    if not match:
        return 'bad'
    number, unit = float(match.group(1)), match.group(2)
    if unit is None:
        return 'zero' if number == 0 else 'unknown'  # only 0 may omit its unit
    if unit not in _ABSOLUTE_UNITS | _PARENT_UNITS | _LAYOUT_UNITS:
        return 'bad'
    if number == 0:
        return 'zero'
    if number < 0:
        return 'bad'
    return 'absolute' if unit in _ABSOLUTE_UNITS else 'relative' if unit in _PARENT_UNITS else 'unknown'


def _math_signs(argument: str):
    """The sign of one min()/max()/clamp() argument when the parent's font size is zero
    and when it is positive ('+', '0', '-' or '?'); 'unresolved' for an expression;
    None when the argument is no length (a bare number, even 0, or an unknown unit)."""
    match = _CSS_DIMENSION.fullmatch(argument)
    if not match:
        return 'unresolved' if re.search(r'\s[-+*/]\s|[*/]', argument) else None
    number, unit = float(match.group(1)), match.group(2)
    sign = '+' if number > 0 else '-' if number < 0 else '0'
    if unit in _ABSOLUTE_UNITS:
        return sign, sign
    if unit in _PARENT_UNITS:
        return '0', sign
    if unit in _LAYOUT_UNITS:
        return '?', '?'
    return None


def _font_size_class(value: str) -> str:
    """'zero', 'visible', 'inherit', 'unresolved' or 'invalid' for one font-size value.

    min(), max() and clamp() over lengths are computed by sign, once with a zero and
    once with a positive parent size, and a negative result is a zero size:
    max(16px, 1rem) is visible, max(-1px, 0px) is zero, max(1em, 0px) follows the
    parent. Every argument must be a length: a bare number (max(16px, 1), even 0) or
    max(16px, garbage) makes the declaration invalid CSS, so it is dropped and the
    inherited size stays. Anything else the parser cannot compute (calc(), var(),
    nested functions, sums, line-height or container units) is unresolved. A positive
    size below 3px, absolute or computed from absolute lengths, is 'tiny': no reader
    reads it, though some clients enforce a minimum.
    """
    if not value or value in {'inherit', 'unset', 'revert', 'revert-layer', 'larger', 'smaller', 'math'}:
        return 'inherit'
    if value in _ABSOLUTE_SIZE_KEYWORDS:
        return 'visible'
    match = re.fullmatch(r'(min|max|clamp)\(([^()]*)\)', value)
    if match:
        function, signs = match.group(1), [_math_signs(argument.strip()) for argument in match.group(2).split(',')]
        if None in signs or (function == 'clamp' and len(signs) != 3):
            return 'invalid'
        if 'unresolved' in signs:
            return 'unresolved'
        pixels = [_absolute_pixels(argument.strip()) for argument in match.group(2).split(',')]
        if None not in pixels:
            result = (max(pixels) if function == 'max' else min(pixels) if function == 'min'
                      else max(pixels[0], min(pixels[1:])))
            return 'visible' if result >= _MIN_VISIBLE_FONT_PX else 'tiny' if result > 0 else 'zero'

        def largest(values):
            return '+' if '+' in values else '?' if '?' in values else '0' if '0' in values else '-'

        def smallest(values):
            return '-' if '-' in values else '?' if '?' in values else '0' if '0' in values else '+'
        sizes = []
        for parent in (0, 1):
            values = [sign[parent] for sign in signs]
            result = (largest(values) if function == 'max' else smallest(values) if function == 'min'
                      else largest([values[0], smallest(values[1:])]))
            sizes.append({'+': 'visible', '?': 'unresolved'}.get(result, 'zero'))
        return {('zero', 'zero'): 'zero', ('visible', 'visible'): 'visible',
                ('zero', 'visible'): 'inherit'}.get(tuple(sizes), 'unresolved')
    if _UNCOMPUTED.search(value):
        return 'unresolved'
    kind = _length_class(value)
    pixels = _absolute_pixels(value)
    if kind == 'absolute' and pixels is not None and pixels < _MIN_VISIBLE_FONT_PX:
        return 'tiny'
    return {'zero': 'zero', 'absolute': 'visible', 'relative': 'inherit',
            'unknown': 'unresolved', 'bad': 'invalid'}[kind]


def _font_size_state(value: str) -> tuple[bool | None, bool]:
    """(zero size, unresolved) of one font-size value; None inherits the parent's size.
    A tiny size is not zero here: the view pass treats it as possibly invisible."""
    kind = _font_size_class(value)
    return {'zero': True, 'visible': False, 'tiny': False}.get(kind), kind == 'unresolved'


# Box geometry that can hide an element's content (hidden-text "salting" in phishing, and
# preheaders in marketing mail).
_GEOMETRY_PROPERTIES = ('max-height', 'height', 'max-width', 'width', 'overflow', 'overflow-x', 'overflow-y',
                        'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
                        'position', 'left', 'top', 'right', 'bottom', 'text-indent', 'clip', 'clip-path',
                        'transform', 'mso-hide')
_PIXELS = {'px': 1, 'pt': 4 / 3, 'pc': 16, 'in': 96, 'cm': 96 / 2.54, 'mm': 96 / 25.4, 'q': 96 / 101.6,
           'em': 16, 'rem': 16}
# Below these, text is invisible to a reader: the opacity of 0.05 or a 1px font.
_NEAR_ZERO_OPACITY = 0.1
_MIN_VISIBLE_FONT_PX = 3


def _css_pixels(value: str):
    """A length in CSS pixels (em and rem at 16px), ('%', n) for percentages and viewport
    units, or None when it is not a plain length."""
    match = _CSS_DIMENSION.fullmatch(value.strip())
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2)
    if unit in {'%', 'vw', 'vh', 'vmin', 'vmax'}:
        return ('%', number)
    if unit is None:
        return 0.0 if number == 0 else None
    return number * _PIXELS[unit] if unit in _PIXELS else None


def _absolute_pixels(value: str):
    """A length in CSS pixels when its unit does not depend on the parent or the viewport
    (rem at 16px), else None."""
    match = _CSS_DIMENSION.fullmatch(value.strip())
    if not match or match.group(2) not in set(_PIXELS) - {'em'}:
        return None
    return float(match.group(1)) * _PIXELS[match.group(2)]


def _opacity_number(value: str):
    """An opacity between 0 and 1, or None when it is not a plain number or percentage."""
    match = re.fullmatch(rf'({_CSS_NUMBER})(%?)', value.strip())
    if not match:
        return None
    return min(1.0, max(0.0, float(match.group(1)) / (100 if match.group(2) else 1)))


def _geometry_hidden(get) -> bool | str:
    """Whether box geometry hides an element's content, from get(property) -> value:
    a zero height or width that clips (overflow hidden or clip, without padding), an
    absolute or fixed position far off screen, a large negative text-indent, a clip
    rectangle or clip path of no area, or a zero scale. 'unresolved' where a value that
    decides it cannot be computed."""
    unresolved = False
    overflow = set(' '.join(get(name) for name in ('overflow', 'overflow-x', 'overflow-y')).split())
    if overflow & {'hidden', 'clip'}:
        for size, paddings in (('height', ('padding-top', 'padding-bottom')), ('width', ('padding-left', 'padding-right'))):
            for name in (f'max-{size}', size):
                value = get(name)
                if not value:
                    continue
                pixels = _css_pixels(value)
                if pixels is None and _UNCOMPUTED.search(value):
                    unresolved = True
                elif pixels == 0 or pixels == ('%', 0.0):
                    padded = [get(item) for item in (*paddings, 'padding') if get(item)]
                    if any(_css_pixels(item.split()[0]) not in (0.0, ('%', 0.0)) for item in padded):
                        unresolved = True
                    else:
                        return True
    if get('position') in {'absolute', 'fixed', 'relative'}:
        for name in ('left', 'top', 'right', 'bottom'):
            pixels = _css_pixels(get(name)) if get(name) else None
            if (isinstance(pixels, tuple) and pixels[1] <= -100) or (
                    isinstance(pixels, float) and pixels <= -1000):
                return True
        clip = re.fullmatch(r'rect\((.*)\)', get('clip'))
        if clip:
            edges = [_css_pixels(edge) for edge in re.split(r'[\s,]+', clip.group(1).strip())]
            if len(edges) == 4 and all(isinstance(edge, float) for edge in edges) and (
                    edges[1] - edges[3] <= 1 and edges[2] - edges[0] <= 1):
                return True
    indent = _css_pixels(get('text-indent').split()[0]) if get('text-indent') else None
    if (isinstance(indent, tuple) and indent[1] <= -100) or (isinstance(indent, float) and indent <= -1000):
        return True
    if re.search(r'inset\(\s*(?:50|100)%|circle\(\s*0(?:px|%)?\s*[)a]', get('clip-path')):
        return True
    if re.search(r'scale[xy]?\(\s*-?0(?:\.0+)?\s*[,)]', get('transform')):
        return True
    return 'unresolved' if unresolved else False


def _hiding_value(name: str, value) -> bool:
    """Whether one declaration can hide content on its own or with another: every display,
    visibility, opacity, font size, colour or unknown value, and the box values that clip
    (a zero size, overflow hidden or clip), move off screen, clip, scale to nothing, or
    hide in Outlook, or a value from var(). A width of 100% or a padding cannot, nor can a
    text or background colour alone."""
    if name in _COLOUR_PROPERTIES:
        return False
    if name not in _GEOMETRY_PROPERTIES:
        return True
    value = value if isinstance(value, str) else ''
    if 'var(' in value:
        return True
    if name in {'max-height', 'height', 'max-width', 'width'}:
        return _css_pixels(value) in (0.0, ('%', 0.0))
    if name in {'overflow', 'overflow-x', 'overflow-y'}:
        return bool({'hidden', 'clip'} & set(value.split()))
    if name in {'left', 'top', 'right', 'bottom', 'text-indent'}:
        pixels = _css_pixels(value.split()[0]) if value else None
        return (isinstance(pixels, tuple) and pixels[1] <= -100) or (isinstance(pixels, float) and pixels <= -1000)
    if name == 'transform':
        return bool(re.search(r'scale[xy]?\(\s*-?0(?:\.0+)?\s*[,)]', value))
    if name == 'mso-hide':
        return value == 'all'
    return name in {'clip', 'clip-path'}


def _zero_box(get) -> bool:
    """A zero height or width: content stays visible unless something clips it."""
    return any(_css_pixels(get(name)) in (0.0, ('%', 0.0)) for name in ('max-height', 'height', 'max-width', 'width')
               if get(name))


def _box_may_hide(get) -> bool:
    """Whether box values may hide content, alone or with values declared elsewhere (an
    off-screen offset with a position set by another rule): hiding geometry, a zero box,
    an off-screen offset, a clip rectangle, or mso-hide."""
    return bool(_geometry_hidden(get) is not False or _zero_box(get) or get('mso-hide')
                or any(_hiding_value(name, get(name)) for name in ('left', 'top', 'right', 'bottom', 'clip')
                       if get(name)))


def _inline_text_state(style: str) -> tuple[bool | None, bool | None, bool]:
    """(zero font size, transparent colour, unresolved) declared by one inline style.

    None means not declared, invalid or inherited, so the parent's state applies. A
    positive absolute size, "initial" or a visible colour restores text inside a
    zero-size or transparent parent; relative sizes (em, %) of a zero size stay zero.
    Values the parser cannot compute (calc(), clamp(), var(), color-mix() and opacity
    calc()) leave the text unresolved, which a descendant cannot undo.
    """
    values = _style_values(style)
    font_size = values.get('font-size', ('', False))[0]
    color = values.get('color', ('', False))[0]
    zero_size, size_unresolved = _font_size_state(font_size)
    opacity = values.get('opacity', ('', False))[0]
    unresolved = (size_unresolved or _color_class(color) == 'unresolved' or '#unrecognised' in values
                  or (opacity.startswith('calc(') and not _inline_visibility(style)[2]))
    return zero_size, _color_state(color), unresolved


def _inline_visibility(style: str) -> tuple[bool, bool | None, bool, bool]:
    """Read bounded visibility declarations, respecting !important."""
    values = _style_values(style)
    display_hidden = values.get('display', ('', False))[0] == 'none'
    visibility = values.get('visibility', ('', False))[0]
    if visibility in {'hidden', 'collapse'}:
        visibility_hidden = True
    elif visibility in {'visible', 'initial'}:
        visibility_hidden = False
    else:
        # inherit/unset/invalid values cannot clear a hidden parent.
        visibility_hidden = None
    opacity = values.get('opacity', ('', False))[0]
    # Zero opacity applies to the entire rendered subtree; children cannot
    # restore it with their own opacity declaration.
    opacity_number = opacity.removesuffix('%')
    opacity_hidden = bool(
        re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', opacity_number)
        and float(opacity_number) <= 0
    ) or bool(re.fullmatch(r'calc\(\s*[+-]?0+(?:\.0+)?%?\s*\)', opacity))
    font_size = values.get('font-size', ('', False))[0]
    color = values.get('color', ('', False))[0]
    uncertain = (_font_size_class(font_size) == 'zero' or _color_class(color) == 'transparent'
                 or '#unrecognised' in values or (opacity.startswith('calc(') and not opacity_hidden))
    return display_hidden, visibility_hidden, opacity_hidden, uncertain


def _strip_css_comments(css: str) -> tuple[str, bool]:
    """Remove real comments while preserving comment-like text in CSS strings.

    Returns the text and whether every string was closed. content:"/*" opens no comment.
    """
    without_comments = []
    quote = None
    index = 0
    while index < len(css):
        character = css[index]
        following = css[index + 1] if index + 1 < len(css) else ''
        if quote:
            without_comments.append(character)
            if character == '\\' and following:
                without_comments.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = css.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character in {'"', "'"}:
            quote = character
            without_comments.append(character)
        else:
            without_comments.append(character)
        index += 1
    return ''.join(without_comments), quote is None


def _stylesheet_may_hide_text(css: str) -> bool:
    """Flag hiding declarations without claiming to implement CSS cascade."""
    # Find balanced rule bodies outside quoted CSS strings. A brace in
    # content:"}" must not end the rule before its hiding declaration.
    cleaned, _complete = _strip_css_comments(css)
    depth = 0
    segment_start = 0
    quote = None
    index = 0
    while index < len(cleaned):
        character = cleaned[index]
        if character == '\\' and index + 1 < len(cleaned):
            index += 2
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == '{':
            if depth:
                display, visibility, opacity, uncertain = _inline_visibility(
                    cleaned[segment_start:index]
                )
                if display or visibility is True or opacity or uncertain:
                    return True
            depth += 1
            segment_start = index + 1
        elif character == '}' and depth:
            display, visibility, opacity, uncertain = _inline_visibility(
                cleaned[segment_start:index]
            )
            if display or visibility is True or opacity or uncertain:
                return True
            depth -= 1
            segment_start = index + 1
        index += 1
    return False


def _split_selectors(prelude: str) -> list[str] | None:
    """Top-level comma-separated selectors, or None for anything this reader does not model."""
    if '\\' in prelude:
        return None
    selectors, current, depth = [], [], 0
    for character in prelude:
        if character in '([':
            depth += 1
        elif character in ')]':
            depth -= 1
        if character == ',' and depth == 0:
            selectors.append(''.join(current).strip())
            current = []
        else:
            current.append(character)
    selectors.append(''.join(current).strip())
    return selectors if depth == 0 else None


def _selector_compounds(selector: str):
    """Compound selectors and the combinators between them, or None if malformed."""
    compounds, combinators, current, depth, pending = [], [], [], 0, None
    for character in selector.strip():
        depth += (character in '([') - (character in ')]')
        if depth == 0 and (character.isspace() or character in '>+~'):
            if current:
                compounds.append(''.join(current))
                current = []
                pending = ' '
            if character in '>+~':
                pending = character
        else:
            if pending and compounds:
                combinators.append(pending)
            pending = None
            current.append(character)
    if current:
        compounds.append(''.join(current))
    if not compounds or len(combinators) != len(compounds) - 1 or depth:
        return None
    return compounds, combinators


_GENERATED_CONTENT = re.compile(r'::|:(?:before|after|first-line|first-letter|marker|placeholder|selection)\b',
                                re.IGNORECASE)
# Pseudo-elements every current browser reads; another one (unknown, or vendor-prefixed
# like ::-moz-selection) makes the browser drop the whole rule it appears in.
_KNOWN_PSEUDO_ELEMENTS = frozenset({
    'before', 'after', 'first-line', 'first-letter', 'marker', 'placeholder', 'selection', 'backdrop',
    'file-selector-button', 'cue', 'grammar-error', 'spelling-error', 'target-text', 'highlight', 'part', 'slotted'})
_COMPOUND_TAG = re.compile(r'\*|[a-zA-Z][\w-]*')
_COMPOUND_PART = re.compile(r'''
    \.(?P<cls>-?[_a-zA-Z][\w-]*)
  | \#(?P<id>-?[_a-zA-Z][\w-]*)
  | \[\s*(?P<name>[a-zA-Z_][\w:-]*)\s*(?:(?P<op>[~|^$*]?=)\s*(?P<value>"[^"]*"|'[^']*'|[^\s\]"']+)\s*(?P<flag>[iIsS])?\s*)?\]
  | :(?P<state>checked|hover|focus-within|focus-visible|focus|active|target)(?![\w-])
  | :(?P<root>root)(?![\w-])
  | :(?P<link>link|any-link|visited)(?![\w-])
''', re.VERBOSE)
# HTML attribute values that selectors compare without regard to case.
_CASELESS_ATTRIBUTES = frozenset({'type', 'align', 'valign', 'dir', 'lang', 'checked', 'disabled', 'method'})


def _parse_compound(text: str):
    """One compound selector as tag, classes, ids, attribute tests and states, or None."""
    if not text:
        return None
    tag, position = None, 0
    match = _COMPOUND_TAG.match(text)
    if match:
        tag = None if match.group() == '*' else match.group().lower()
        position = match.end()
    typed = bool(tag)
    classes, ids, attributes, states, extra, visited = [], [], [], [], 0, False
    while position < len(text):
        match = _COMPOUND_PART.match(text, position)
        if not match:
            return None
        if match.group('root'):
            # :root is the html element, with a pseudo-class's specificity.
            if tag not in {None, 'html'}:
                return None
            tag, extra = 'html', extra + 1
        elif match.group('link'):
            # :link is a link with a destination: an attribute test's specificity. :visited
            # styles only links the reader has followed, and only their colour.
            visited |= match.group('link') == 'visited'
            attributes.append(('href', None, None, False))
        elif match.group('cls'):
            classes.append(match.group('cls'))
        elif match.group('id'):
            ids.append(match.group('id'))
        elif match.group('name'):
            value = match.group('value')
            if value is not None and value[:1] in {'"', "'"}:
                value = value[1:-1]
            name = match.group('name').lower()
            attributes.append((name, match.group('op'), value,
                               (match.group('flag') or '').lower() == 'i' or name in _CASELESS_ATTRIBUTES))
        else:
            states.append(match.group('state').lower())
        position = match.end()
    key = ((tag or '*') + ''.join(f'.{name}' for name in classes) + ''.join(f'#{name}' for name in ids)
           + ''.join(f'[{name}{operator or ""}{value or ""}{" i" if caseless else ""}]'
                     for name, operator, value, caseless in attributes))
    return {'tag': tag, 'classes': tuple(classes), 'ids': tuple(ids), 'attributes': tuple(attributes),
            'states': tuple(states), 'key': key, 'extra': extra, 'typed': typed, 'visited': visited}


def _document_features(html: str) -> dict:
    """Elements of an HTML document as (tag, classes, id, attributes), and the tags, classes,
    ids and attribute names they use, read by the same parser as the text (character
    references decoded, the first of a repeated attribute kept, conditional comments open)."""
    features = {'tags': set(), 'classes': set(), 'ids': set(), 'attributes': set(), 'nodes': []}

    class Elements(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)

        def handle_starttag(self, tag, attrs):
            attributes = {name: value or '' for name, value in _first_html_attributes(attrs).items()}
            classes = tuple(attributes.get('class', '').split())
            element_id = attributes.get('id', '').strip()
            features['tags'].add(tag)
            features['attributes'].update(attributes)
            features['classes'].update(name.casefold() for name in classes)
            if element_id:
                features['ids'].add(element_id.casefold())
            features['nodes'].append((tag, classes, element_id, attributes))
    _collect_html(Elements, html)
    return features


# Hooks mail clients put around a message: classes and ids that template CSS targets to
# style one client, grouped by client. Absent from the document, they still match there.
_CLIENT_HOOKS = {
    'gmail': {'classes': frozenset({'ii', 'gt', 'a6s'}), 'ids': frozenset()},
    'outlook-web': {'classes': frozenset({'externalclass'}), 'ids': frozenset({'messageviewbody'})},
    'apple': {'classes': frozenset({'applebody', 'applefooter'}), 'ids': frozenset()},
    'outlook': {'classes': frozenset(), 'ids': frozenset({'outlook'})},
}
_CLIENT_ATTRIBUTES = {'data-ogsc': 'outlook-dark', 'data-ogsb': 'outlook-dark', 'data-ogac': 'outlook-dark',
                      'data-ogab': 'outlook-dark', 'x-apple-data-detectors': 'apple', 'owa': 'outlook-web'}


def _client_family(compound: dict, combinator: str, features: dict):
    """The mail client whose wrapper a leading compound selects (u + .body for Gmail,
    [data-ogsc] for Outlook dark mode), or None. Only hooks absent from the document count."""
    if compound['states'] or compound['ids'] and compound['classes']:
        return None
    if (compound['tag'] == 'u' and not (compound['classes'] or compound['ids'] or compound['attributes'])
            and combinator in {'+', '~'}):
        return 'gmail'
    if compound['tag'] and compound['tag'] not in {'html', 'body', 'div', 'table'}:
        return None
    families = set()
    for name in compound['classes']:
        folded = name.casefold()
        if folded in features['classes']:
            return None
        families.update(family for family, hooks in _CLIENT_HOOKS.items() if folded in hooks['classes'])
    for name in compound['ids']:
        folded = name.casefold()
        if folded in features['ids']:
            return None
        families.update(family for family, hooks in _CLIENT_HOOKS.items() if folded in hooks['ids'])
    for name, *_rest in compound['attributes']:
        if name in features['attributes']:
            return None
        families.add(_CLIENT_ATTRIBUTES.get(name, f'[{name}]'))
    hooks = len(compound['classes']) + len(compound['ids']) + len(compound['attributes'])
    return families.pop() if hooks and len(families) == 1 else None


def _compound_absent(compound: dict, features: dict) -> bool:
    """Whether the document has nothing a compound requires, so only a mail client could add it."""
    return bool((compound['tag'] and compound['tag'] not in features['tags'])
                or any(name.casefold() not in features['classes'] for name in compound['classes'])
                or any(name.casefold() not in features['ids'] for name in compound['ids'])
                or any(name not in features['attributes'] for name, *_rest in compound['attributes']))


def _loose_subject(selector: str, text: str):
    """A superset of what a selector this reader cannot match exactly may select: its last
    compound without pseudo-classes, or None (any element). Specificity is over-estimated."""
    subject = _parse_compound(re.sub(r':[\w-]+(?:\([^)]*\))?', '', text or '') or '*')
    specificity = (0, selector.count('#') + 1, selector.count('.') + selector.count('[')
                   + selector.count(':') + 1, len(re.findall(r'[a-zA-Z]+', selector)))
    return subject, specificity


def _parse_selector(selector: str, features: dict):
    """How one selector is matched: ('exact', pattern), ('maybe', subject, specificity),
    ('root', specificity, subject) for the html or body element a document leaves implied,
    or ('skip',) for generated content or a compound the document lacks.

    An exact pattern is matched element by element. Leading client hooks (u + .body,
    [data-ogsc], #MessageViewBody) are inserted by a mail client: the pattern applies in
    that client's views. An interaction state (:checked, :hover) on a compound is a
    condition, one per compound and state. Selectors this reader cannot match exactly
    (:not(), :first-child, implied table sections) are "maybe": text their subject could
    select is unresolved wherever they could change it.
    """
    split = _selector_compounds(selector)
    if split is None:
        return ('maybe', *_loose_subject(selector, ''))
    texts, combinators = split
    if _GENERATED_CONTENT.search(texts[-1]):
        names = re.findall(r'::?([\w-]+)', texts[-1])
        if all(name.lower() in _KNOWN_PSEUDO_ELEMENTS for name in names if f'::{name}' in texts[-1]):
            return ('skip',)
        return ('maybe', *_loose_subject(selector, texts[-1]))
    compounds = [_parse_compound(text) for text in texts]
    if (any(compound is None for compound in compounds)
            or any(compound['tag'] in {'tbody', 'thead', 'tfoot'} for compound in compounds)
            or any(combinator == '>' and left['tag'] == 'table' and right['tag'] in {'tr', 'td', 'th'}
                   for combinator, left, right in zip(combinators, compounds, compounds[1:]))):
        return ('maybe', *_loose_subject(selector, texts[-1]))
    if any(compound['visited'] for compound in compounds):
        return ('skip',)
    subject = compounds[-1]
    if (len(compounds) == 1 and subject['tag'] in {'html', 'body'} and subject['tag'] not in features['tags']
            and not (subject['classes'] or subject['ids'] or subject['attributes'] or subject['states'])):
        # The browser's implied html and body: everything inherits from them.
        return ('root', (0, 0, subject['extra'], int(subject['typed'])), subject)
    if _compound_absent(compounds[-1], features):
        return ('skip',)
    first, rooted, client = 0, False, set()
    for index, compound in enumerate(compounds[:-1]):
        bare = not (compound['classes'] or compound['ids'] or compound['attributes'] or compound['states'])
        family = _client_family(compound, combinators[index], features)
        if bare and compound['tag'] in {'html', 'body'} and compound['tag'] not in features['tags']:
            # The browser's implied root: an ancestor of everything, the parent of top-level elements.
            first, rooted = index + 1, combinators[index] == '>'
        elif family:
            first, rooted = index + 1, False
            client.add(family)
        else:
            break
    if len(client) > 1:
        return ('skip',)  # hooks of two clients never hold together
    if any(_compound_absent(compound, features) for compound in compounds[first:]):
        return ('skip',)  # nothing in the document matches, in any client
    kept, links = compounds[first:], combinators[first:]
    key = ' '.join([kept[0]['key'], *(compound['key'] if link == ' ' else f'{link} {compound["key"]}'
                                      for link, compound in zip(links, kept[1:]))])
    return ('exact', {
        'compounds': kept, 'combinators': links, 'rooted': rooted,
        'client': next(iter(client), None),
        'states': tuple(dict.fromkeys((compound['key'], state) for compound in kept for state in compound['states'])),
        'specificity': (0, sum(len(compound['ids']) for compound in compounds),
                        sum(len(compound['classes']) + len(compound['attributes']) + len(compound['states'])
                            + compound['extra'] for compound in compounds),
                        sum(1 for compound in compounds if compound['typed'])),
        'key': ('^ ' if rooted else '') + key,
    })


def _substitute_variables(value: str, custom: dict, depth: int = 0):
    """value with each var(--name[, fallback]) replaced from the element's custom properties,
    or None when one is undefined without a fallback (invalid at computed-value time)."""
    if depth > 8:
        return None
    result, index = [], 0
    while True:
        start = value.find('var(', index)
        if start < 0:
            result.append(value[index:])
            return ''.join(result)
        result.append(value[index:start])
        level, end = 0, start + 3
        for end in range(start + 3, len(value)):
            level += (value[end] == '(') - (value[end] == ')')
            if level == 0:
                break
        else:
            return None
        inner = value[start + 4:end]
        level, split = 0, len(inner)
        for position, character in enumerate(inner):
            level += (character == '(') - (character == ')')
            if character == ',' and level == 0:
                split = position
                break
        name, fallback = inner[:split].strip(), inner[split + 1:] if split < len(inner) else None
        replacement = custom.get(name, fallback)
        if replacement is None:
            return None
        replacement = _substitute_variables(replacement.strip(), custom, depth + 1)
        if replacement is None:
            return None
        result.append(replacement)
        index = end + 1


def _variable_class(name: str, value):
    """The class of a font-size, color or opacity value after var() substitution. A value
    that cannot be substituted, or is invalid, makes the declaration unset: size and colour
    inherit, opacity stays 1."""
    if value is None:
        return False if name == 'opacity' else 'inherit'
    if name == 'opacity':
        opacity = _opacity_number(value)
        if opacity is None:
            return 'unresolved' if _UNCOMPUTED.search(value) else False
        return True if opacity <= 0 else 'faint' if opacity < _NEAR_ZERO_OPACITY else False
    kind = _font_size_class(value) if name == 'font-size' else _color_class(value)
    return 'inherit' if kind == 'invalid' else kind


def _with_custom_properties(winners: dict, custom: dict) -> tuple:
    """An element's winning declarations with var() substituted, and its custom properties.

    Custom properties inherit; an element's own (--name) replace its parent's, and var()
    in them reads the element's own values first. A size, colour or opacity read from
    var() is classified; a box value takes the substituted text, or is dropped when it
    cannot be substituted (it is then unset, as in browsers)."""
    defined = [name for name in winners if name.startswith('--')]
    if defined:
        raw = dict(custom)
        for name in defined:
            value = winners[name][3]
            if value == 'initial':
                raw.pop(name, None)
            elif value not in {'inherit', 'unset', 'revert', 'revert-layer'}:
                raw[name] = value
        custom = dict(raw)
        for name in defined:
            if name in raw and 'var(' in raw[name]:
                substituted = _substitute_variables(raw[name], raw)
                if substituted is None:
                    del custom[name]
                else:
                    custom[name] = substituted
    resolved = winners
    for name, ranked in winners.items():
        value = ranked[3]
        if isinstance(value, tuple) and value[0] == 'var':
            value = _variable_class(name, _substitute_variables(value[1], custom))
        elif (name in _GEOMETRY_PROPERTIES or name in _COLOUR_PROPERTIES or name in _BACKGROUND_LAYOUT_PROPERTIES) \
                and isinstance(value, str) and 'var(' in value:
            value = _substitute_variables(value, custom)
        else:
            continue
        if resolved is winners:
            resolved = dict(winners)
        if value is None:
            del resolved[name]
        else:
            resolved[name] = (*ranked[:3], value)
    return resolved, custom


def _declared_values(block: str, *, typography: bool = True, geometry: bool = False, colours: bool = False) -> list:
    """The declarations of one rule or style attribute that decide whether text renders,
    as (property, value, !important). display, visibility and opacity take True (hidden)
    or False; visibility also 'inherit'; font-size and color take 'zero' or 'transparent',
    'visible', 'inherit' or 'unresolved'. An unknown display, visibility or opacity value
    is ('unknown', 'unresolved'). A size, colour or opacity from var() is ('var', value),
    resolved per element; custom properties (--name) keep their value. With colours, the
    text colour ('text-color') and background ('background-color', 'background-image',
    'background-clip') keep their values too."""
    values = _style_values(block)
    declared = []
    if 'display' in values:
        declared.append(('display', values['display'][0] == 'none', values['display'][1]))
    if 'visibility' in values:
        value = values['visibility'][0]
        declared.append(('visibility', True if value in {'hidden', 'collapse'} else
                         False if value in {'visible', 'initial'} else 'inherit', values['visibility'][1]))
    if 'opacity' in values:
        value = values['opacity'][0]
        opacity = _opacity_number(value)
        declared.append(('opacity', ('var', value) if 'var(' in value else
                         (True if opacity <= 0 else 'faint' if opacity < _NEAR_ZERO_OPACITY else False)
                         if opacity is not None else 'unresolved' if value.startswith('calc(') else False,
                         values['opacity'][1]))
    if typography and 'font-size' in values:
        value = values['font-size'][0]
        declared.append(('font-size', ('var', value) if 'var(' in value else _font_size_class(value),
                         values['font-size'][1]))
    if typography and 'color' in values:
        value = values['color'][0]
        declared.append(('color', ('var', value) if 'var(' in value else _color_class(value), values['color'][1]))
    declared.extend((name, value, important) for name, (value, important) in values.items() if name.startswith('--'))
    if colours:
        declared.extend((name, *values[name]) for name in _BACKGROUND_LAYOUT_PROPERTIES if name in values)
        if 'color' in values:
            declared.append(('text-color', values['color'][0], values['color'][1]))
        declared.extend((name, values[name][0], values[name][1]) for name in ('background-color', 'background-image')
                        if name in values)
    if geometry:
        declared.extend((name, values[name][0], values[name][1]) for name in _GEOMETRY_PROPERTIES if name in values)
    if '#unrecognised' in values:
        declared.append(('unknown', 'unresolved', False))
    return declared


def _stylesheet_hides_geometry(css: str) -> bool:
    """Whether any rule sets box values that may hide content (see _box_may_hide), a tiny
    font, a faint opacity, or any of them, a size or a colour from var()."""
    cleaned, _complete = _strip_css_comments(css)
    for block in re.findall(r'\{([^{}]*)\}', cleaned):
        values = _style_values(block)

        def get(name):
            return values.get(name, ('', False))[0]
        opacity = _opacity_number(get('opacity'))
        if (_box_may_hide(get) or _font_size_class(get('font-size')) == 'tiny'
                or (opacity is not None and opacity < _NEAR_ZERO_OPACITY)
                or any('var(' in get(name) for name in ('font-size', 'color', 'opacity', *_GEOMETRY_PROPERTIES))):
            return True
    return False


def _stylesheet_hides_typography(css: str) -> bool:
    """Whether any rule sets a zero or tiny font size, a transparent text colour, or either
    from var()."""
    cleaned, _complete = _strip_css_comments(css)
    return any(value in {'zero', 'tiny', 'transparent'} or 'var(' in _style_values(block).get(name, ('', False))[0]
               for block in re.findall(r'\{([^{}]*)\}', cleaned)
               for name, value, _important in _declared_values(block) if name in {'font-size', 'color'})


def _cascade_state(parent: tuple, winners: dict) -> tuple:
    """An element's rendering state in one view, from its parent's and the winning
    declarations: ((display none, visibility hidden, opacity zero, zero font size
    (or 'tiny'), transparent colour, clipped by box geometry or faint, hidden in
    Outlook, the colour of its background, text colour (r, g, b, alpha), backdrop
    (r, g, b)), unresolved). A colour is None where it cannot be known: a background
    image, a system colour."""
    (display_none, visibility_hidden, opacity_zero, font_zero, transparent, clipped, outlook_hidden,
     _same, colour, backdrop) = parent
    unresolved = bool(winners.get('unknown'))
    geometry = _geometry_hidden(lambda name: winners[name][3] if name in winners else '')
    unresolved |= geometry == 'unresolved'
    clipped = clipped or geometry is True
    outlook_hidden = outlook_hidden or bool(winners.get('mso-hide') and winners['mso-hide'][3] == 'all')
    ranked = winners.get('display')
    display_none = display_none or bool(ranked and ranked[3] is True)
    ranked = winners.get('visibility')
    if ranked and isinstance(ranked[3], bool):
        visibility_hidden = ranked[3]
    ranked = winners.get('opacity')
    if ranked:
        unresolved |= ranked[3] == 'unresolved'
        opacity_zero = opacity_zero or ranked[3] is True
        clipped = clipped or ranked[3] == 'faint'
    ranked = winners.get('font-size')
    if ranked:
        unresolved |= ranked[3] == 'unresolved'
        if ranked[3] in {'zero', 'tiny', 'visible'}:
            # A child restores a zero or tiny size with a readable one of its own.
            font_zero = {'zero': True, 'tiny': 'tiny', 'visible': False}[ranked[3]]
    ranked = winners.get('color')
    if ranked:
        unresolved |= ranked[3] == 'unresolved'
        if ranked[3] in {'transparent', 'visible'}:
            transparent = ranked[3] == 'transparent'
    ranked = winners.get('text-color')
    if ranked and ranked[3] not in {'inherit', 'unset', 'revert', 'revert-layer', 'currentcolor'}:
        colour = _DEFAULT_TEXT if ranked[3] == 'initial' else _colour_rgba(ranked[3])
    image, fill = winners.get('background-image'), winners.get('background-color')
    painted, solid = _background_parts(image[3])[1:] if image else (False, None)
    if solid and not _background_covers(image[3], *(winners[name][3] if name in winners else None
                                                    for name in ('background-size', 'background-repeat'))):
        # A one-colour gradient that does not tile the whole box paints only part of it.
        painted, solid = True, None
    ranked = winners.get('background-clip')
    clip = _background_clip(ranked[3]) if ranked and isinstance(ranked[3], str) else 'none'
    if clip != 'none' and transparent:
        # background-clip: text paints the background inside the glyphs, where transparent
        # text shows it (gradient text).
        if painted or solid or (fill and _background_parts(fill[3])[0] not in {None, 'transparent'}):
            transparent, colour = False, None
            unresolved |= clip == 'unknown'
    # A declaration browsers may keep or drop (env(), an untyped math function, a clip from
    # either) leaves both its own background and the one it would replace possible.
    uncertain = clip == 'unknown' or any(
        isinstance(winners[name][3], str) and _background_uncertain(winners[name][3])
        for name in ('background-image', 'background-color', *_BACKGROUND_LAYOUT_PROPERTIES) if name in winners)
    if uncertain:
        backdrop = None
    elif clip == 'all':
        pass  # painted inside the glyphs only: the backdrop stays the parent's
    elif painted or clip == 'some':
        backdrop = None
    else:
        # A background paints behind the element's text and its descendants', its colour
        # first and a one-colour gradient over it; a translucent one blends with what is
        # behind it.
        for token in (_background_parts(fill[3])[0] if fill else None, solid):
            if not token:
                continue
            paint = colour if token == 'currentcolor' else _colour_rgba(token)
            if paint is None or (paint[3] < 1 and backdrop is None):
                backdrop = None
            elif paint[3] > 0:
                backdrop = paint[:3] if paint[3] >= 1 else tuple(round(channel) for channel in _blend(paint, backdrop))
    return (display_none, visibility_hidden, opacity_zero, font_zero, transparent, clipped, outlook_hidden,
            _same_colour(colour, backdrop), colour, backdrop), unresolved


# The document root: nothing hidden, black text on a white canvas.
_ROOT_STATE = (False,) * 8 + (_DEFAULT_TEXT, _DEFAULT_CANVAS)
# Children a table part keeps; browsers move anything else out of the table.
_TABLE_CONTENT_MODEL = {
    'table': frozenset({'caption', 'colgroup', 'col', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th',
                        'script', 'style', 'template'}),
    **{section: frozenset({'tr', 'td', 'th', 'script', 'style', 'template'}) for section in ('thead', 'tbody', 'tfoot')},
    'tr': frozenset({'td', 'th', 'script', 'style', 'template'}),
}
# Rendering conditions whose every combination is a view (2**5 = 32 views), each in no
# client or in one; more is unmodelled.
_MAX_MEDIA_CONTEXTS = 5
_MAX_RENDERING_VIEWS = 64


def _stylesheet_cascade(css: str, html: str = '', *, typography: bool = True, geometry: bool = True,
                        colours: bool = False):
    """The stylesheet rules that decide which text of an HTML document renders.

    Returns None if unmodelled (CSS nesting, a hiding @-rule, an unreadable selector in a
    hiding rule, more than five conditions). Otherwise {"patterns", "index", "conditions",
    "views", "contexts"}. Conditions are @media contexts, mail-client wrappers and
    interaction states; every combination of them is a view. A view holds, per pattern,
    the winning declaration of each property as (!important, specificity, source
    position, value), and the "maybe" rules that apply in it. The reader matches patterns element
    by element and takes the highest declaration, with the inline style, as CSS does.
    """
    cleaned, complete = _strip_css_comments(css)
    if not complete:
        return None
    features = _document_features(html)
    # Custom properties var() reads anywhere: a rule setting one may hide text elsewhere.
    read_variables = frozenset(re.findall(r'var\(\s*(--[\w-]+)', css + html))
    patterns, pattern_ids, maybe, events, position, clients, root_events = [], {}, [], [], 0, {}, []
    shared_states = {}

    def shared(condition, compound):
        # A state of a compound several elements match cannot be one condition: each
        # element has its own (two checkboxes with the same class).
        if condition not in shared_states:
            shared_states[condition] = sum(_compound_matches(compound, node, True)
                                           for node in features['nodes']) > 1
        return shared_states[condition]

    preludes, start, index = [], 0, 0
    quote = None
    while index < len(cleaned):
        character = cleaned[index]
        if character == '\\':
            index += 2
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == ';' and not preludes:
            # A statement at-rule (@import, @charset, @namespace) ends here, not at a
            # block: it is no part of the next rule's selector. Imported CSS is external.
            start = index + 1
        elif character == '{':
            prelude = cleaned[start:index].strip()
            if preludes and not preludes[-1].startswith('@') and ':' in prelude.split(';')[0]:
                return None  # nested declarations (CSS nesting) are not modelled
            preludes.append(prelude)
            start = index + 1
        elif character == '}' and preludes:
            prelude = preludes.pop()
            block = cleaned[start:index]
            start = index + 1
            declared = _declared_values(block, typography=typography, geometry=geometry, colours=colours)
            values = _style_values(block)

            def get(name):
                return values.get(name, ('', False))[0]
            hides = any((value is True or isinstance(value, tuple) or value in {'zero', 'transparent', 'unresolved'}
                         or name in read_variables) and name not in _COLOUR_PROPERTIES
                        for name, value, _important in declared) or (
                geometry and _box_may_hide(get))
            if declared and prelude.startswith('@'):
                if hides:
                    return None
            elif declared:
                # Conditional @-rules are contexts. Others (@layer, @scope) change the
                # cascade itself, which is not modelled.
                if any(item.startswith('@') and not re.match(r'@(?:media|supports|container)\b', item, re.IGNORECASE)
                       for item in preludes):
                    return None
                media = ' '.join(re.sub(r'\s+', ' ', item) for item in preludes if item.startswith('@'))
                selectors = _split_selectors(prelude)
                if selectors is None and hides:
                    return None
                parsed_list = [_parse_selector(selector, features) for selector in selectors or ()] or [
                    ('maybe', None, (0, 9, 9, 9))]
                if any(parsed[0] == 'maybe' for parsed in parsed_list):
                    # Browsers drop a whole rule for one selector they cannot read, so no
                    # selector of a list with one this reader cannot match is certain to apply.
                    parsed_list = [('maybe', parsed[1]['compounds'][-1], parsed[1]['specificity'])
                                   if parsed[0] == 'exact' else ('maybe', parsed[2], parsed[1])
                                   if parsed[0] == 'root' else parsed for parsed in parsed_list]
                for parsed in parsed_list:
                    position += 1
                    if parsed[0] == 'skip':
                        continue
                    if parsed[0] == 'exact' and any(
                            shared(condition, compound) for compound in parsed[1]['compounds']
                            for condition in [(compound['key'], state) for state in compound['states']]):
                        parsed = ('maybe', parsed[1]['compounds'][-1], parsed[1]['specificity'])
                    if parsed[0] == 'maybe':
                        maybe.append((media, parsed[1], parsed[2], declared, position))
                        continue
                    if parsed[0] == 'root':
                        root_events.extend((frozenset(filter(None, (media,))), name, (important, parsed[1], position, value))
                                           for name, value, important in declared)
                        continue
                    pattern = parsed[1]
                    pattern_id = pattern_ids.setdefault(pattern['key'], len(patterns))
                    if pattern_id == len(patterns):
                        patterns.append(pattern)
                    if pattern['client']:
                        # Patterns are shared by structure: the client belongs to this rule.
                        clients.setdefault(pattern['client'])
                    conditions = frozenset(filter(None, (media, pattern['client'], *pattern['states'])))
                    for name, value, important in declared:
                        events.append((conditions, pattern_id, name,
                                       (important, pattern['specificity'], position, value)))
        index += 1
    clients = list(clients)

    def needed():
        found = [condition for condition in dict.fromkeys(
            condition for event in (*events, *root_events) for condition in event[0]) if condition not in clients]
        return found + list(dict.fromkeys(media for media, *_rest in maybe if media and media not in found))

    def too_many(found):
        return len(found) > _MAX_MEDIA_CONTEXTS or (1 << len(found)) * (1 + len(clients)) > _MAX_RENDERING_VIEWS

    conditions = needed()
    if colours and too_many(conditions):
        # Colour rules under more @media contexts than are modelled may or may not apply:
        # as "maybe" rules they can make text possibly invisible, never certain. A dark-mode
        # context stays one: its colours assume the client's dark canvas.
        demoted = {condition for condition in conditions if isinstance(condition, str)
                   and not re.search(r'prefers-color-scheme\s*:\s*dark', condition, re.IGNORECASE)
                   and all(name in _COLOUR_PROPERTIES or name == 'color'
                           for required, _pattern_id, name, _ranked in events if condition in required)
                   and not any(condition in required for required, *_rest in root_events)}
        grouped = {}
        for required, pattern_id, name, ranked in events:
            if required & demoted:
                grouped.setdefault((pattern_id, ranked[1], ranked[2]), []).append((name, ranked[3], ranked[0]))
        events = [event for event in events if not event[0] & demoted]
        maybe.extend((None, patterns[pattern_id]['compounds'][-1], specificity, declared, position)
                     for (pattern_id, specificity, position), declared in grouped.items())
        conditions = needed()
    if too_many(conditions):
        return None
    views = []
    for client, mask in product([None, *clients], range(1 << len(conditions))):
        active = {condition for bit, condition in enumerate(conditions) if mask >> bit & 1} | {client}
        winners, root = {}, {}
        for required, pattern_id, name, ranked in events:
            declared = winners.setdefault(pattern_id, {})
            if required <= active and (name not in declared or ranked[:3] > declared[name][:3]):
                declared[name] = ranked
        for required, name, ranked in root_events:
            if required <= active and (name not in root or ranked[:3] > root[name][:3]):
                root[name] = ranked
        # In dark mode a client paints its own canvas and default text colour; Outlook's
        # recolours the message's own colours too.
        dark = 'client' if client == 'outlook-dark' else 'scheme' if any(isinstance(condition, str) and re.search(
            r'prefers-color-scheme\s*:\s*dark', condition, re.IGNORECASE) for condition in active) else None
        views.append({'winners': winners, 'root': root, 'dark': dark, 'maybe': [
            (subject, {name: (important, specificity, position, value) for name, value, important in declared})
            for media, subject, specificity, declared, position in maybe if not media or media in active]})
    index_by = {'class': {}, 'id': {}, 'tag': {}, 'any': []}
    for pattern_id, pattern in enumerate(patterns):
        subject = pattern['compounds'][-1]
        if subject['ids']:
            index_by['id'].setdefault(subject['ids'][0].casefold(), []).append(pattern_id)
        elif subject['classes']:
            index_by['class'].setdefault(subject['classes'][0].casefold(), []).append(pattern_id)
        elif subject['tag']:
            index_by['tag'].setdefault(subject['tag'], []).append(pattern_id)
        else:
            index_by['any'].append(pattern_id)
    return {'patterns': patterns, 'index': index_by, 'conditions': conditions + clients, 'views': views,
            'contexts': bool(conditions or clients), 'geometry': geometry, 'variables': read_variables,
            'colours': colours,
            # Patterns with combinators whose rules can change what renders, for content a
            # browser moves out of a table.
            'structural': [patterns[pattern_id] for pattern_id in sorted(
                {pattern_id for _required, pattern_id, name, ranked in events if _hiding_value(name, ranked[3])})
                if len(patterns[pattern_id]['compounds']) > 1]}


def _compound_matches(compound: dict | None, node: tuple, fold: bool) -> bool:
    """Whether one element (tag, classes, id, attributes) matches a compound selector.
    None stands for any element. fold compares class and id names regardless of case."""
    if compound is None:
        return True
    tag, classes, element_id, attributes = node
    if compound['tag'] and compound['tag'] != tag:
        return False
    if fold:
        folded = {name.casefold() for name in classes}
        if not (all(name.casefold() in folded for name in compound['classes'])
                and all(name.casefold() == (element_id or '').casefold() for name in compound['ids'])):
            return False
    elif not (set(compound['classes']) <= set(classes) and all(name == element_id for name in compound['ids'])):
        return False
    for name, operator, expected, caseless in compound['attributes']:
        actual = attributes.get(name)
        if actual is None:
            return False
        if operator is None:
            continue
        if caseless or (fold and name in {'class', 'id'}):
            actual, expected = actual.casefold(), expected.casefold()
        if not ((operator == '=' and actual == expected)
                or (operator == '~=' and expected in actual.split())
                or (operator == '|=' and (actual == expected or actual.startswith(expected + '-')))
                or (operator == '^=' and expected and actual.startswith(expected))
                or (operator == '$=' and expected and actual.endswith(expected))
                or (operator == '*=' and expected and expected in actual)):
            return False
    return True


def _visible_content_text(text: str, parse_warnings=None, *, structure_stats=None, readings=None) -> str:
    """Decode HTML text separately from destinations, preserving inline words."""
    class TextCollector(_AnalysisHTMLParser):
        head_elements = {'html', 'head', 'base', 'basefont', 'bgsound', 'link',
                         'meta', 'title', 'noscript', 'noframes', 'script', 'style', 'template'}

        def __init__(self, targets=None, colour_views=True):
            super().__init__(convert_charrefs=True)
            # targets is set only in the rendering-view pass (see readings below).
            self.targets = targets
            # Whether the views leave out text the colour of its background.
            self.colour_views = colour_views
            self.strict_parts = []
            self.outlook_parts = []
            self.certain_parts = []
            views = targets['views'] if targets else []
            # Per view, an element's state: display none, visibility hidden, opacity zero,
            # zero font size, transparent colour, clipped by its box, hidden in Outlook
            # (mso-hide), the colour of its background, its text and backdrop colours;
            # and its custom properties. The document root takes the rules on the html
            # and body elements a document leaves implied.
            self.root_states, self.root_custom, self.root_tokens = (), (), frozenset()
            if targets:
                self._cascade_root()
            self.view_parts = [[] for _view in views] if targets and targets['contexts'] else []
            # The same readings with images off: linked images show their alt text in place.
            self.parts_off, self.certain_parts_off = [], []
            self.strict_parts_off, self.outlook_parts_off = [], []
            self.view_parts_off = [[] for _parts in self.view_parts]
            self.images_off = False
            # What every view shows, plus text whose rendering is undecidable: text rules
            # read it too, so an undecidable rule cannot hide a scam from them.
            self.loose_parts = []
            # Element siblings at each depth, as (tag, classes, id, attributes), so that
            # selectors with combinators are matched exactly.
            self.children = [[]]
            # Text whose rendering this reader cannot decide (a selector it cannot match
            # exactly, a value it cannot compute, names matched only regardless of case).
            self.cascade_conflict = False
            # Text box geometry or mso-hide conceals in some view, and letters only their
            # background's colour does.
            self.box_hidden_text = False
            self.same_colour_letters = 0
            # Text and background colours the document uses, to decide whether any text
            # may be the colour of its background.
            self.text_colours, self.backgrounds = set(), set()
            self.hidden_parts = []
            self.outlook_only = 0
            self.hidden_from_outlook = 0
            self.parts = []
            self.hidden = []
            self.elements = []
            self.excluded_hidden_text = False
            self.hidden_characters = 0
            self.linked_visible_images = 0
            self.stylesheet_parts = []
            self.style_mode = ''
            # Inline box geometry that may hide content (or mso-hide): the view pass then
            # cascades box properties too.
            self.geometry_hint = False
            self.conditional_image_alt = False
            # A fallback instruction ("Enter password") stays unresolved for the model.
            self.alt_instruction = False
            self.uncertain_inline_style = False
            self.open_paragraph = False
            # In the view pass, each link's label as every view shows it: the text inside
            # an <a href> that the view renders, children a rule hides left out.
            self.anchors = []
            self.anchors_overflow = False
            self.open_anchors = []

        def _anchor_record(self, href):
            views = len(self.view_parts)
            return {'href': href, 'certain': [], 'certain_off': [], 'outlook': [], 'outlook_off': [], 'loose': [],
                    'views': [[] for _view in range(views)], 'views_off': [[] for _view in range(views)]}

        def _visually_hidden(self):
            return bool(self.elements and (self.elements[-1][1] or self.elements[-1][2]))

        def _emit(self, text, tokens=None, inline=None, *, states=None, images_off=False):
            # images_off: an image's fallback text, rendered only when images are off.
            if not images_off:
                self.parts.append(text)
            self.parts_off.append(text)
            if inline is None:
                inline = bool(self.elements) and any(self.elements[-1][6])
            # Only text a zero-size or transparent style actually reaches is uncertain.
            if inline and text.strip() and not images_off:
                self.uncertain_inline_style = True
            if self.targets is None:
                return
            if tokens is None:
                tokens = self.elements[-1][5] if self.elements else self.root_tokens
            if states is None:
                states = self.elements[-1][7] if self.elements else self.root_states
            if '#ambiguous' in tokens and text.strip():
                self.cascade_conflict = True
            same = [state[7] and self.colour_views for state in states]
            shown = [not any(state[:6]) and not hidden for state, hidden in zip(states, same)]
            in_outlook = not any(state[6] for state in states)
            if text.strip() and any(state[5] or state[6] or state[3] == 'tiny' for state in states):
                self.box_hidden_text = True
            if not images_off and any(hidden and not any(state[:6]) for state, hidden in zip(states, same)):
                self.same_colour_letters += sum(character.isalnum() for character in text)
            if not images_off and (all(shown) or '#ambiguous' in tokens):
                self.loose_parts.append(text)
            # Certain text renders in every view; each @media context shows its own.
            if all(shown):
                for parts, wanted in ((self.certain_parts, True), (self.strict_parts, not self.outlook_only),
                                      (self.outlook_parts, not self.hidden_from_outlook and in_outlook)):
                    if wanted and not images_off:
                        parts.append(text)
                for parts, wanted in ((self.certain_parts_off, True), (self.strict_parts_off, not self.outlook_only),
                                      (self.outlook_parts_off, not self.hidden_from_outlook and in_outlook)):
                    if wanted:
                        parts.append(text)
            if not self.outlook_only:
                for parts, parts_off, visible in zip(self.view_parts, self.view_parts_off, shown):
                    if visible:
                        if not images_off:
                            parts.append(text)
                        parts_off.append(text)
            if self.open_anchors:
                # The same text, as the label of the innermost open link.
                anchor = self.anchors[self.open_anchors[-1][1]]
                if not images_off and (all(shown) or '#ambiguous' in tokens):
                    anchor['loose'].append(text)
                if all(shown):
                    if not images_off:
                        anchor['certain'].append(text)
                    anchor['certain_off'].append(text)
                    if not self.hidden_from_outlook and in_outlook:
                        if not images_off:
                            anchor['outlook'].append(text)
                        anchor['outlook_off'].append(text)
                if not self.outlook_only:
                    for parts, parts_off, visible in zip(anchor['views'], anchor['views_off'], shown):
                        if visible:
                            if not images_off:
                                parts.append(text)
                            parts_off.append(text)

        def _matches(self, pattern, position, level, index, fold):
            # Right to left, as browsers match: the open element at a level is the last
            # entry of its siblings, and the parent of every entry at the next level.
            if not _compound_matches(pattern['compounds'][position], self.children[level][index], fold):
                return False
            if position == 0:
                return not pattern['rooted'] or level == 0
            combinator = pattern['combinators'][position - 1]
            if combinator in {'+', '~'}:
                earlier = [index - 1] if combinator == '+' else range(index - 1, -1, -1)
                return any(self._matches(pattern, position - 1, level, sibling, fold)
                           for sibling in earlier if sibling >= 0)
            ancestors = [level - 1] if combinator == '>' else range(level - 1, -1, -1)
            return any(self._matches(pattern, position - 1, ancestor, len(self.children[ancestor]) - 1, fold)
                       for ancestor in ancestors if ancestor >= 0)

        def _outside_table(self):
            """Where browsers put content a table cannot hold: the innermost open table's
            parent (index into the open elements, -1 for the root), or None."""
            tables = [index for index, element in enumerate(self.elements) if element[0] == 'table']
            return tables[-1] - 1 if tables else None

        def _maybe_changes(self, view, node, parent, custom, winners, state, element_custom):
            """How rules this reader cannot match exactly, applying to node (None for the
            implied root), may change it: 'ambiguous' if one may change whether its text
            renders or a custom property var() reads, 'same' if one may only give its text
            the colour of its background, else None."""
            found = None
            for subject, declared in view['maybe']:
                if subject is not None and not (
                        _compound_matches(subject, node, True) if node is not None else
                        subject['tag'] in {None, 'html', 'body'} and not (subject['classes'] or subject['ids']
                                                                         or subject['attributes'])):
                    continue
                # A rule applies whole: its declarations that outrank the winners apply together
                # (a white text colour with the dark background beside it hides nothing).
                outranking = {name: ranked for name, ranked in declared.items()
                              if name not in winners or ranked[:3] > winners[name][:3]}
                if not outranking:
                    continue
                resolved, changed = _with_custom_properties({**winners, **outranking}, custom)
                possible = _cascade_state(parent, resolved)[0]
                if possible[:7] != state[:7] or any(
                        name in self.targets['variables'] and changed.get(name) != element_custom.get(name)
                        for name in outranking):
                    return 'ambiguous'
                if possible[7] and not state[7] and subject is not None and (
                        subject['classes'] or subject['ids'] or subject['attributes']):
                    # Only a rule aimed at a class, id or attribute: a bare tag stands for
                    # every element of it, with a specificity this reader over-estimates.
                    found = 'same'
            return found

        def _cascade_root(self):
            states, customs, ambiguous = [], [], False
            for view in self.targets['views']:
                # A client in dark mode paints its own canvas and default text colour.
                parent = (*_ROOT_STATE[:8], None, None) if view['dark'] else _ROOT_STATE
                resolved, custom = _with_custom_properties(view['root'], {})
                state, unresolved = _cascade_state(parent, resolved)
                change = None if unresolved else self._maybe_changes(view, None, parent, {}, view['root'], state, custom)
                ambiguous |= unresolved or change == 'ambiguous'
                if change == 'same':
                    state = (*state[:7], True, *state[8:])
                states.append(state)
                customs.append(custom)
            self.root_states, self.root_custom = tuple(states), tuple(customs)
            self.root_tokens = frozenset({'#ambiguous'}) if ambiguous else frozenset()

        def _cascade_element(self, tag, attrs, style, fostered=False):
            """Record an element among its siblings; return its markers, and its per-view
            states and custom properties."""
            values = dict(attrs)
            node = (tag, tuple((values.get('class') or '').split()), (values.get('id') or '').strip(),
                    {name: value or '' for name, value in attrs})
            level = len(self.elements)
            self.children[level].append(node)
            cascade = self.targets
            candidates = set(cascade['index']['any']) | set(cascade['index']['tag'].get(tag, ()))
            for name in node[1]:
                candidates.update(cascade['index']['class'].get(name.casefold(), ()))
            if node[2]:
                candidates.update(cascade['index']['id'].get(node[2].casefold(), ()))
            matched, ambiguous = [], False
            last = len(self.children[level]) - 1
            for pattern_id in candidates:
                pattern = cascade['patterns'][pattern_id]
                final = len(pattern['compounds']) - 1
                if self._matches(pattern, final, level, last, False):
                    matched.append(pattern_id)
                elif self._matches(pattern, final, level, last, True):
                    ambiguous = True  # matches only if names ignore case, as in quirks mode
            inline = _declared_values(style, geometry=cascade['geometry'], colours=cascade['colours'])
            hidden_attribute = 'hidden' in values
            # Presentational colours (bgcolor, <font color>) and the browser's link colour
            # yield to any author rule, as the hidden attribute does.
            hints = _colour_hints(tag, values) if cascade['colours'] else {}
            parents = self.elements[-1][7] if self.elements else self.root_states
            customs = self.elements[-1][8] if self.elements else self.root_custom
            outside = self._outside_table() if fostered else None
            if outside is not None:
                # Browsers move this element before the table: it inherits from outside it.
                # Selectors that reach it through the table's elements cannot be decided.
                parents = self.elements[outside][7] if outside >= 0 else self.root_states
                customs = self.elements[outside][8] if outside >= 0 else self.root_custom
                chain = [self.children[index][-1] for index in range(outside + 1, len(self.elements))]
                ambiguous |= any(set(pattern['combinators']) & {'+', '~'} or any(
                    _compound_matches(compound, node, True) for compound in pattern['compounds'][:-1] for node in chain)
                    for pattern in cascade['structural'])
            states, element_customs = [], []
            for view, parent, custom in zip(cascade['views'], parents, customs):
                winners = {}
                for pattern_id in matched:
                    for name, ranked in view['winners'].get(pattern_id, {}).items():
                        if name not in winners or ranked[:3] > winners[name][:3]:
                            winners[name] = ranked
                for name, value, important in inline:
                    # An inline style outranks every selector; !important still decides first.
                    ranked = (important, (1, 0, 0, 0), 0, value)
                    if name not in winners or ranked[:3] > winners[name][:3]:
                        winners[name] = ranked
                if hidden_attribute and 'display' not in winners:
                    winners['display'] = (False, (0, 0, 0, 0), 0, True)
                if view['dark'] == 'client':
                    # Outlook's dark mode recolours text and backgrounds: their colours are unknown.
                    for name in _COLOUR_PROPERTIES:
                        winners.pop(name, None)
                else:
                    for name, value in hints.items():
                        if name not in winners:
                            winners[name] = (False, (0, 0, 0, 0), 0, value)
                resolved, element_custom = _with_custom_properties(winners, custom)
                state, unresolved = _cascade_state(parent, resolved)
                ambiguous = ambiguous or unresolved
                if not ambiguous:
                    change = self._maybe_changes(view, node, parent, custom, winners, state, element_custom)
                    ambiguous = change == 'ambiguous'
                    if change == 'same':
                        # A rule this reader cannot match may give the text its background's
                        # colour: possibly invisible, like a tiny font.
                        state = (*state[:7], True, *state[8:])
                states.append(state)
                element_customs.append(element_custom)
            markers = (self.elements[-1][5] if self.elements else self.root_tokens) & {'#ambiguous'}
            return (markers | {'#ambiguous'} if ambiguous else markers), tuple(states), tuple(element_customs)

        def _truncate_elements(self, index):
            if self.open_paragraph and any(item[0] == 'p' for item in self.elements[index:]):
                self.open_paragraph = False
            while self.open_anchors and self.open_anchors[-1][0] >= index:
                self.open_anchors.pop()
            del self.elements[index:]
            del self.children[index + 1:]

        def _implicitly_close(self, tag):
            if tag in {'td', 'th', 'tr'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'table':
                        break
                    if tag in {'td', 'th'} and existing == 'tr':
                        break
                    if existing in ({'td', 'th'} if tag in {'td', 'th'} else {'tr'}):
                        self._truncate_elements(index)
                        break
            if self.open_paragraph and tag in _P_IMPLIED_END_START_TAGS:
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'p':
                        self._truncate_elements(index)
                        break
            if tag == 'li':
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing in {'ul', 'ol', 'menu'}:
                        break
                    if existing == 'li':
                        self._truncate_elements(index)
                        break
            if tag in {'dt', 'dd'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'dl':
                        break
                    if existing in {'dt', 'dd'}:
                        self._truncate_elements(index)
                        break

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            # A head end tag is optional: body content implicitly closes it.
            # Do not do this inside title/script/style or inert template text.
            if self.hidden == ['head'] and tag not in self.head_elements:
                self.hidden.pop()
            if tag == 'head' and 'head' in self.hidden:
                return
            if tag == 'style' and 'template' not in self.hidden:
                # Browsers apply a style element only as CSS, and only for its media.
                values = dict(attrs)
                media = (values.get('media') or '').strip()
                self.style_mode = ('ignore' if (values.get('type') or '').strip().lower() not in {'', 'text/css'}
                                   or re.search(r'[{};]', media) else
                                   media if media and media.lower() not in {'all', 'screen'} else '')
                if self.style_mode not in {'', 'ignore'}:
                    self.stylesheet_parts.append(f'@media {self.style_mode} {{')
            if self.targets is not None and not self.hidden and tag in {'script', 'style', 'template', 'noframes'}:
                # Not rendered, but an element all the same: sibling selectors count it
                # (p + p does not match across a <style> between them).
                values = dict(attrs)
                self.children[len(self.elements)].append(
                    (tag, tuple((values.get('class') or '').split()), (values.get('id') or '').strip(),
                     {name: value or '' for name, value in attrs}))
            if tag in {'script', 'style', 'head', 'title', 'template', 'noframes'}:
                self.hidden.append(tag)
            if self.hidden:
                return
            self._implicitly_close(tag)
            if tag == 'a':
                # HTML closes a prior anchor when another anchor starts. Do not
                # inherit an old HTTP action through a nested mailto/fragment link.
                self.elements = [(*element[:4], False, *element[5:]) if element[0] == 'a' else element
                                 for element in self.elements]
            # Browsers retain the first duplicate attribute, not the last.
            style = next((value for name, value in attrs if name == 'style'), '')
            display_hidden, visibility_hidden, opacity_hidden, _uncertain = _inline_visibility(style or '')
            parent_display = self.elements[-1][1] if self.elements else False
            parent_visibility = self.elements[-1][2] if self.elements else False
            element_display = (parent_display or any(name == 'hidden' for name, _ in attrs)
                               or display_hidden or opacity_hidden)
            element_visibility = parent_visibility if visibility_hidden is None else visibility_hidden
            # Zero size, transparent colour and uncertain opacity as inherited here. A child
            # can restore the first two (font-size:14px inside a font-size:0 layout wrapper).
            zero_size, transparent, opacity_uncertain = _inline_text_state(style or '')
            if self.targets is None and style and re.search(
                    r'height|width|position|left|top|right|bottom|indent|clip|transform|mso-hide|font-size|opacity',
                    style, re.IGNORECASE):
                values = _style_values(style)

                def get(name):
                    return values.get(name, ('', False))[0]
                opacity = _opacity_number(get('opacity'))
                self.geometry_hint |= bool(_box_may_hide(get) or _font_size_class(get('font-size')) == 'tiny'
                                           or (opacity is not None and 0 < opacity < _NEAR_ZERO_OPACITY))
            if self.targets is None:
                hints = _colour_hints(tag, dict(attrs))
                self.text_colours.update(filter(None, (hints.get('text-color'),)))
                self.backgrounds.update(filter(None, (hints.get('background-color'),)))
                if style and re.search(r'color|background', style, re.IGNORECASE):
                    values = _style_values(style)
                    self.text_colours.update(values[name][0] for name in ('color',) if name in values)
                    self.backgrounds.update(values[name][0] for name in ('background-color', 'background-image',
                                                                         'background-clip') if name in values)
            parent_inline = self.elements[-1][6] if self.elements else (False, False, False)
            inline_state = (parent_inline[0] if zero_size is None else zero_size,
                            parent_inline[1] if transparent is None else transparent,
                            parent_inline[2] or opacity_uncertain)
            inline_uncertain = any(inline_state)
            # In the view pass, the stylesheet and inline cascade per view; '#ambiguous'
            # marks content whose rendering this reader cannot decide.
            element_tokens, element_states, element_custom = frozenset(), None, None
            if self.targets is not None:
                parent = self.elements[-1][0] if self.elements else None
                fostered = parent in _TABLE_CONTENT_MODEL and tag not in _TABLE_CONTENT_MODEL[parent] and not (
                    tag == 'input' and (dict(attrs).get('type') or '').strip().lower() == 'hidden')
                element_tokens, element_states, element_custom = self._cascade_element(tag, attrs, style or '', fostered)
            if tag == 'source' and any(name == 'srcset' and value and value.strip()
                                       for name, value in attrs):
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'picture':
                        picture = self.elements[index]
                        self.elements[index] = (*picture[:3], True, *picture[4:])
                        break
            if (tag == 'img' and not element_display and not element_visibility
                    and any(element[4] for element in self.elements)
                    and any(name in {'src', 'srcset'} and value and value.strip() for name, value in attrs)):
                self.linked_visible_images += 1
            if tag == 'img':
                alt = next((value for name, value in attrs if name == 'alt'), '') or ''
                if alt.strip():
                    if self.targets is None and (element_display or element_visibility):
                        self.excluded_hidden_text = True
                        self.hidden_parts.append(alt)
                    elif (not any(name in {'src', 'srcset'} and value and value.strip()
                                  for name, value in attrs)
                          and not any(element[0] == 'picture' and element[3]
                                      for element in self.elements)):
                        # With no image resource, HTML's replacement text is
                        # the text the reader can see or hear.
                        for piece in (' ', alt, ' '):
                            self._emit(piece, element_tokens, inline_uncertain, states=element_states)
                    else:
                        # A two-word decorative label such as "Company logo"
                        # should not disable scoring of an otherwise text-rich
                        # email. Longer fallback instructions may change what a
                        # reader sees when images fail or are blocked.
                        instruction = bool(re.search(
                            r'\b(?:enter|provide|send|share|submit|type|verify|confirm|reset|update)\s+'
                            r'(?:(?:your|the|a)\s+)?(?:password|passcode|otp|one-time password|'
                            r'credit card number|account)\b', alt, re.IGNORECASE,
                        ))
                        description = (sum(not char.isspace() for char in alt) >= 12
                                       and (len(re.findall(r'\w+', alt, flags=re.UNICODE)) >= 3
                                            or bool(non_latin_script_segments(alt, 12))))
                        self.conditional_image_alt |= instruction or description
                        self.alt_instruction |= instruction
                        # With images off (blocked, or not loading) the alt text shows in place.
                        self.images_off = True
                        self._emit(f' {alt} ', element_tokens, inline_uncertain, states=element_states,
                                   images_off=True)
            if tag not in _HTML_VOID_ELEMENTS:
                href = dict(attrs).get('href') or ''
                actionable_anchor = False
                if tag == 'a' and re.sub(r'[\t\r\n]', '', href).strip().lower().startswith(('http://', 'https://')):
                    try:
                        target = _parse_link_target(href)
                        actionable_anchor = target.scheme.lower() in {'http', 'https'} and bool(target.hostname)
                    except ValueError:
                        pass
                self.elements.append((tag, element_display, element_visibility, False, actionable_anchor,
                                      element_tokens, inline_state, element_states, element_custom))
                self.children.append([])
                if actionable_anchor and self.targets is not None:
                    if len(self.anchors) < _MAX_VIEW_ANCHORS:
                        self.anchors.append(self._anchor_record(href))
                        self.open_anchors.append((len(self.elements) - 1, len(self.anchors) - 1))
                    else:
                        self.anchors_overflow = True
                if tag == 'p':
                    self.open_paragraph = True
            if not element_display and not element_visibility and tag in {'p', 'div', 'br', 'li', 'tr', 'td', 'hr', 'section'}:
                self._emit(' ', element_tokens)

        def handle_endtag(self, tag):
            if self.hidden == ['head'] and tag in {'body', 'html', 'br'}:
                self.hidden.pop()
            if self.hidden and tag == self.hidden[-1]:
                self.hidden.pop()
                if tag == 'style' and self.style_mode not in {'', 'ignore'}:
                    self.stylesheet_parts.append('}')
                if tag == 'style':
                    self.style_mode = ''
                return
            for index in range(len(self.elements) - 1, -1, -1):
                if self.elements[index][0] == tag:
                    self._truncate_elements(index)
                    break
            if not self.hidden and not self._visually_hidden() and tag in {'p', 'div', 'li', 'tr', 'td', 'section'}:
                self._emit(' ')

        def collect_data(self, data):
            if self.targets is not None and _RENDERING_SENTINELS.search(data):
                for piece in re.split('([\ue000-\ue003])', data):
                    if piece in {'\ue000', '\ue001'}:
                        self.outlook_only = max(0, self.outlook_only + (1 if piece == '\ue000' else -1))
                    elif piece in {'\ue002', '\ue003'}:
                        self.hidden_from_outlook = max(0, self.hidden_from_outlook + (1 if piece == '\ue002' else -1))
                    elif piece:
                        self._collect_text(piece)
                return
            self._collect_text(data)

        def _collect_text(self, data):
            if self.hidden == ['head'] and data.strip():
                self.hidden.pop()
            if self.hidden:
                if self.hidden[-1] == 'style' and 'template' not in self.hidden[:-1] and self.style_mode != 'ignore':
                    self.stylesheet_parts.append(data)
                return
            if (self.targets is not None and data.strip() and self.elements
                    and self.elements[-1][0] in _TABLE_CONTENT_MODEL and self._outside_table() is not None):
                # Browsers move text out of a table: it inherits from outside it.
                outside = self._outside_table()
                self._emit(data, self.elements[outside][5] if outside >= 0 else self.root_tokens,
                           states=self.elements[outside][7] if outside >= 0 else self.root_states)
            elif self.targets is None and self._visually_hidden():
                self.hidden_characters += sum(not char.isspace() for char in _strip_invisible_format_controls(data))
                if data.strip():
                    self.excluded_hidden_text = True
                    self.hidden_parts.append(data)
            else:
                self._emit(data)

    collector = _collect_html(TextCollector, text, parse_warnings)
    if collector.excluded_hidden_text and parse_warnings is not None:
        parse_warnings.append(_HIDDEN_HTML_TEXT_WARNING)
    if parse_warnings is not None and _stylesheet_may_hide_text(''.join(collector.stylesheet_parts)):
        parse_warnings.append(_STYLESHEET_VISIBILITY_WARNING)
    if collector.uncertain_inline_style and parse_warnings is not None:
        parse_warnings.append(_INLINE_CSS_VISIBILITY_WARNING)
    if collector.conditional_image_alt and parse_warnings is not None:
        parse_warnings.append(_IMAGE_ALT_FALLBACK_WARNING)
    visible = re.sub(r'\s+', ' ', ''.join(collector.parts)).strip()
    if readings is not None:
        # Other plausible renderings, for the model to check that uncertain text cannot
        # change its answer: the strictest non-Outlook and Outlook views (without text a
        # stylesheet or zero-size/transparent style may hide), and the visible text plus
        # definitely hidden text, and with images off, the visible text plus the fallback
        # descriptions of linked images. None of them replaces the visible text. A
        # fallback instruction such as "Enter password" stays unresolved: it is beyond
        # the model's judgement.
        stylesheet = ''.join(collector.stylesheet_parts)
        geometry = collector.geometry_hint or _stylesheet_hides_geometry(stylesheet)
        text_colours, backgrounds = _stylesheet_colours(stylesheet)
        colours = _colours_may_match(collector.text_colours | text_colours, collector.backgrounds | backgrounds)
        others = (collector.uncertain_inline_style or collector.conditional_image_alt
                  or collector.excluded_hidden_text or _stylesheet_may_hide_text(stylesheet) or geometry
                  or (parse_warnings is not None and _MSO_CONDITIONAL_WARNING in parse_warnings))
        uncertain = others or colours
        def joined(parts):
            return re.sub(r'\s+', ' ', ''.join(parts)).strip()
        if uncertain:
            # All the text, whatever styles may hide: the request and lure rules that set a
            # floor read it too (analyze_email_content), so a misjudged style cannot clear a
            # scam. It is never a model rendering.
            readings['all_text'] = joined([visible, ' ', *collector.hidden_parts])
        if collector.images_off:
            # Text rules always read the fallback text of linked images in place.
            readings['images_off'] = joined(collector.parts_off)
        if uncertain:
            typography = collector.uncertain_inline_style or _stylesheet_hides_typography(stylesheet)
            targets = _stylesheet_cascade(stylesheet, text, typography=typography, geometry=geometry, colours=colours)
            if targets is None and colours:
                # Colour rules may add more conditions than are modelled: render without colours.
                targets = _stylesheet_cascade(stylesheet, text, typography=typography, geometry=geometry)
            unresolved, views, model_views = [], None, None
            if targets is not None:
                views = model_views = _collect_html(lambda: TextCollector(targets), text, [], mark=True,
                                                    unresolved=unresolved)
                if views.cascade_conflict:
                    unresolved.append('cascade')
                if views.anchors_overflow:
                    # Labels past the budget are not followed through the views.
                    unresolved.append('links')
                readings['same_colour_letters'] = views.same_colour_letters
                if 0 < views.same_colour_letters < _SAME_COLOUR_MODEL_LETTERS:
                    # Too little to dilute the model (a preheader): its views keep this
                    # text, and only the text rules also read the message without it.
                    model_views = _collect_html(lambda: TextCollector(targets, colour_views=False), text, [],
                                                mark=True) if others else None
                elif not others and not views.same_colour_letters:
                    # Colours that could match, but no text has its background's colour.
                    views = model_views = None
                if model_views is not None and (model_views.box_hidden_text or model_views.same_colour_letters) \
                        and parse_warnings is not None and _POSSIBLY_INVISIBLE_WARNING not in parse_warnings:
                    parse_warnings.append(_POSSIBLY_INVISIBLE_WARNING)
            if others or model_views is not None:
                readings['resolved'] = (model_views is not None and not unresolved
                                        and not collector.alt_instruction)
            if views is not None and 'malformed' not in unresolved:
                # Text rules may read what no style can hide, and what each context
                # shows, even where the model's renderings stay unresolved (fallback
                # instructions, odd conditional comments, undecidable rules).
                readings['certain'] = joined(views.certain_parts)
                if model_views is not None:
                    readings['media'] = [joined(parts) for parts in model_views.view_parts]
                # Text rules read each view, the Outlook view, and undecidable text too.
                readings['rules_media'] = [*(joined(parts) for parts in views.view_parts), joined(views.outlook_parts)] + (
                    [joined(views.loose_parts)] if views.cascade_conflict else [])
                # Each link's label as each of these readings shows it.
                def labels(key, index=None):
                    return [(joined(anchor[key] if index is None else anchor[key][index]), anchor['href'])
                            for anchor in views.anchors]
                readings['certain_links'] = labels('certain')
                readings['links_complete'] = not views.anchors_overflow
                readings['rules_media_links'] = [*(labels('views', index) for index in range(len(views.view_parts))),
                                                 labels('outlook')] + ([labels('loose')] if views.cascade_conflict else [])
                if collector.images_off:
                    readings['certain_off'] = joined(views.certain_parts_off)
                    if model_views is not None:
                        readings['media_off'] = [joined(parts) for parts in model_views.view_parts_off]
                    readings['rules_media_off'] = [*(joined(parts) for parts in views.view_parts_off),
                                                   joined(views.outlook_parts_off)]
                    readings['certain_links_off'] = labels('certain_off')
                    readings['rules_media_links_off'] = [*(labels('views_off', index)
                                                           for index in range(len(views.view_parts_off))),
                                                         labels('outlook_off')]
            if readings.get('resolved'):
                readings.update(strict=joined(model_views.strict_parts), outlook=joined(model_views.outlook_parts),
                                hidden=joined([visible, ' ', *collector.hidden_parts]))
                readings.update({f'media_{index}': text for index, text in enumerate(readings['media'])})
                if collector.images_off:
                    readings.update(strict_off=joined(model_views.strict_parts_off),
                                    outlook_off=joined(model_views.outlook_parts_off))
                    readings.update({f'media_{index}_off': text for index, text in enumerate(readings['media_off'])})
    if structure_stats is not None:
        structure_stats.update(hidden_characters=collector.hidden_characters,
                               visible_characters=sum(not char.isspace() for char in _strip_invisible_format_controls(visible)),
                               linked_visible_images=collector.linked_visible_images)
    return visible


# Links whose label is followed through each rendering view: more than a message within the
# 60,000-byte upload limit can hold (a link needs 19 bytes at least). Past it, the rest are
# matched by their plain label and the rendering counts as unresolved.
_MAX_VIEW_ANCHORS = 5000


def _unescape_css(value: str) -> str:
    value = re.sub(r'\\(?:\r\n|[\n\r\f])', '', value)
    def replacement(match):
        if match.group(1):
            codepoint = int(match.group(1), 16)
            return chr(codepoint) if 0 < codepoint <= 0x10ffff else '\ufffd'
        return match.group(2)

    return re.sub(r'\\(?:([0-9a-fA-F]{1,6})(?:[ \t\n\r\f])?|([^\n\r\f]))',
                  replacement, value)
