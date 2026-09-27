"""Russian brands for the typosquat rule — data/typosquat_targets_ru.json.

The global list (data/typosquat_targets.json) had no Russian brand, so
sberbamk.ru, t1nkoff.ru, 0zon.ru and wildberies.ru were invisible to the
rule. A brand here is a family of legitimate sites, and every one of them
the rule does not know is a false positive, so each entry carries more than
a name and a domain. Every exemption maps to the evidence for it:

  names             the spellings compared (sberbank, sber, сбербанк) and
                    the site each one's look-alikes are told they imitate
  official          registrable domains the brand's owner runs
                    (wildberries.kz, yandex.md, alfa-bank.by …)
  unrelated         someone else's site of the same shape (mts.ca is
                    Manitoba's phone company, avito.ma a Moroccan site)
  not_typos         labels one edit from a name that are words or other
                    companies' names (zoon, aviso, mt5), under any TLD
  no_tld_confusion  names whose bare form other companies own abroad
                    (Tele2 AB's tele2.se, mts.rs): the name under another
                    TLD is not reported, only its look-alikes
  no_fuzzy          names with too few distinctive letters for edit
                    distance (tele2 = 'tele' + a digit, and tele5.de is a TV
                    channel; ozon + a letter is ozone, gozon, mozon):
                    look-alikes, swaps, hyphens and combos still count

Why each brand is in or out is written in the file's _meta. A malformed
file is logged and yields no brands; the global list keeps working.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

logger = logging.getLogger("cleanway.ru_brands")

DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "typosquat_targets_ru.json"


@dataclass(frozen=True)
class BrandGroup:
    """One owner's brand names and every domain that must not be flagged."""

    key: str
    owner: str
    names: Mapping[str, str]
    official: frozenset[str]
    unrelated: frozenset[str]
    not_typos: frozenset[str]
    no_tld_confusion: frozenset[str]
    no_fuzzy: frozenset[str]


def idn_forms(domain: str) -> frozenset[str]:
    """A domain in both spellings the scorer may hold it in: the ASCII
    (punycode) wire form and the decoded Unicode form."""
    d = domain.lower().strip(".")
    forms = {d}
    try:
        forms.add(d.encode("idna").decode("ascii"))
    except UnicodeError:
        pass
    if "xn--" in d:
        try:
            forms.add(d.encode("ascii").decode("idna"))
        except UnicodeError:
            pass
    return frozenset(forms)


def _all_forms(domains: Iterable[str]) -> frozenset[str]:
    return frozenset(f for d in domains for f in idn_forms(d))


def _require(cond: bool, key: str, what: str) -> None:
    if not cond:
        raise ValueError(f"{key}: {what}")


def _evidence_map(raw: dict, field: str, key: str) -> dict[str, str]:
    """An optional field mapping an item to the evidence for it."""
    value = raw.get(field, {})
    _require(isinstance(value, dict), key, f"'{field}' must map each entry to its evidence")
    for item, why in value.items():
        _require(isinstance(item, str) and item == item.lower().strip(), key, f"{field}: bad entry {item!r}")
        _require(isinstance(why, str) and bool(why.strip()), key, f"{field}: {item!r} needs its evidence")
    return value


def parse_group(key: str, raw: Any) -> BrandGroup:
    """One entry of 'brands'. Raises ValueError naming the entry."""
    _require(isinstance(raw, dict), key, "must be an object")
    names = raw.get("names")
    _require(isinstance(names, dict) and bool(names), key, "'names' must map name -> domain")
    for name, domain in names.items():
        _require(isinstance(name, str) and name == name.lower() and len(name) >= 2, key, f"bad name {name!r}")
        _require(isinstance(domain, str) and "." in domain, key, f"bad domain for {name!r}")
    official = _evidence_map(raw, "official", key)
    unrelated = _evidence_map(raw, "unrelated", key)
    not_typos = _evidence_map(raw, "not_typos", key)
    no_tld = _evidence_map(raw, "no_tld_confusion", key)
    no_fuzzy = _evidence_map(raw, "no_fuzzy", key)
    for domain in [*official, *unrelated]:
        _require("." in domain and "/" not in domain, key, f"{domain!r} is not a registrable domain")
    for label in not_typos:
        _require("." not in label, key, f"not_typos: {label!r} must be a label, not a domain")
    _require(all(d in official for d in names.values()), key, "every name's domain must be in 'official'")
    _require(not set(official) & set(unrelated), key, "a domain is either official or unrelated")
    _require(set(no_tld) <= set(names) and set(no_fuzzy) <= set(names), key, "switches must name a name")
    return BrandGroup(
        key=key,
        owner=str(raw.get("owner", "")),
        names=MappingProxyType({n: d.lower() for n, d in names.items()}),
        official=_all_forms(official),
        unrelated=_all_forms(unrelated),
        not_typos=frozenset(not_typos),
        no_tld_confusion=frozenset(no_tld),
        no_fuzzy=frozenset(no_fuzzy),
    )


def parse(data: Any) -> tuple[BrandGroup, ...]:
    """The whole file. Raises ValueError on any malformed entry or on a name
    listed by two groups."""
    brands = data.get("brands") if isinstance(data, dict) else None
    if not isinstance(brands, dict):
        raise ValueError("'brands' must be an object")
    groups = tuple(parse_group(k, v) for k, v in brands.items())
    seen: dict[str, str] = {}
    for g in groups:
        for name in g.names:
            if name in seen:
                raise ValueError(f"{g.key}: name {name!r} is also listed by {seen[name]}")
            seen[name] = g.key
    return groups


def load(path: Optional[Path] = None) -> tuple[BrandGroup, ...]:
    """The Russian brand groups; () when the file is missing or malformed."""
    p = path or DATA_PATH
    try:
        return parse(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:  # json.JSONDecodeError is a ValueError
        logger.warning("Failed to load %s: %s — Russian brands not compared", p.name, e)
        return ()
