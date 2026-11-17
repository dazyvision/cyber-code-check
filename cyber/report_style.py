"""Présentation et échappement communs aux rapports statiques."""

import html
import re
from urllib.parse import urlsplit


def _h(value):
    return html.escape(str(value if value is not None else "Non renseigné"), quote=True)


def _md(value):
    text = html.escape(str(value if value is not None else "Non renseigné"), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text).replace("\r", " ").replace("\n", " ")


def _source_link(url):
    if urlsplit(url).scheme != "https":
        return _h(url)
    return f'<a href="{_h(url)}" rel="noreferrer">Consulter la source ↗</a>'


CSS = """
:root{color-scheme:light;--ink:#182c25;--muted:#52665d;--paper:#f4f5ef;--line:#d5ddd3;--accent:#254b3e}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 system-ui,-apple-system,sans-serif}
header{background:var(--ink);color:#f5f6ef;padding:28px max(5vw,24px) 52px}.top{display:flex;justify-content:space-between;gap:20px;font:12px ui-monospace,monospace;letter-spacing:.12em;border-bottom:1px solid #466054;padding-bottom:22px}.brand{font-weight:800;letter-spacing:.22em}.eyebrow{font:12px ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase}header .eyebrow{color:#bcceb8;margin-top:38px}h1{font-size:clamp(32px,5vw,56px);font-weight:550;letter-spacing:-.045em;line-height:1.1;margin:14px 0}header p{max-width:800px;color:#d2dfcf}.scope{display:inline-block;border:1px solid #6d8b79;padding:4px 12px;border-radius:30px;font-size:12px}
main{max-width:1200px;margin:auto;padding:30px 5vw 60px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{border:1px solid var(--line);border-radius:12px;padding:22px;background:white}.stat strong{display:block;font-size:36px;line-height:1.2;font-weight:550}.stat span{font-size:12px;color:var(--muted)}nav{display:flex;gap:24px;flex-wrap:wrap;padding:26px 0;border-bottom:1px solid var(--line)}a{color:#23513f;text-underline-offset:4px}h2{font-size:26px;letter-spacing:-.03em;font-weight:550;margin:32px 0 8px}h3{font-size:18px;margin:12px 0}.muted{color:var(--muted)}.note{padding:18px 20px;border-left:3px solid #879b77;background:#e8eee2;margin:24px 0}.inventory{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.component{background:#fff;border:1px solid var(--line);border-radius:10px;padding:20px}.component p{margin:6px 0}.chip{display:inline-block;font:11px ui-monospace,monospace;background:#eef1e9;border-radius:5px;padding:3px 8px;vertical-align:middle}.flow{background:white;padding:15px 18px;margin:8px 0;border:1px solid var(--line);border-radius:8px}.flow p{margin:5px 0}.diagram{overflow:auto;background:#eaeee5;border-radius:14px;margin:20px 0;padding:10px}.diagram svg{display:block;width:100%;min-width:530px}.svg-kind{font:11px ui-monospace,monospace;fill:#52665d;letter-spacing:1px}.svg-title{font:19px system-ui,sans-serif;fill:#182c25}.svg-zone{font:12px system-ui,sans-serif;fill:#52665d}
details{border:1px solid var(--line);background:#fff;border-radius:10px;margin:10px 0;overflow:hidden}summary{cursor:pointer;padding:17px 20px;display:list-item;margin-left:16px}summary strong{font-weight:600}summary .muted{font-size:12px;display:block;margin:5px 0 0}.result-body{border-top:1px solid var(--line);padding:8px 22px 22px}.badge{display:inline-block;font-size:11px;border-radius:20px;padding:3px 9px;margin-right:8px;font-weight:650}.fail{background:#f8e6df;color:#983a25}.unknown{background:#f4edd3;color:#785d11}.pass{background:#deecdf;color:#305c36}.not_applicable{background:#edefec;color:#526057}dl{display:grid;grid-template-columns:150px 1fr;gap:12px;font-size:14px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.legend{font-size:13px;color:var(--muted)}footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.source-list li{margin:8px 0;overflow-wrap:anywhere}p,li{overflow-wrap:anywhere}code{font:12px ui-monospace,monospace}
@media(max-width:650px){.stats{grid-template-columns:repeat(2,1fr)}.inventory{grid-template-columns:1fr}.top{flex-direction:column;gap:8px}dl{grid-template-columns:1fr;gap:5px}dd{margin-bottom:10px}main{padding:24px 18px}nav{gap:14px}.stat{padding:16px}}
@media print{header{background:white;color:black;padding:10px}header p,header .eyebrow{color:black}main{padding:10px;max-width:none}.stats{break-inside:avoid}details{break-inside:avoid}nav{display:none}a{color:black}.result-body{display:block}summary{list-style:none}.diagram{break-inside:avoid}}
"""
