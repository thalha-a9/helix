"""
Helix — Subject location conflict detection.

An optional known location for the subject refines judgement: when a candidate
profile *states* a location that cannot be reconciled with it, the finding is
flagged loudly before the investigator confirms it. Location is never required,
and an absent or unreadable location never counts against a candidate.

Extraction is deliberately conservative. Only explicit location markers are
read (profile "Location:" fields, JSON location keys, pin emoji, "based in"),
never bare place names scanned out of whole pages — a country name in a footer,
a cookie banner or a nav menu is not a claim about the subject.
"""

import re
from typing import Dict, List, Set

# ── Gazetteer: canonical country → aliases (names, demonyms, ISO3, cities) ────
# Matched case-insensitively on word boundaries. Two-letter ISO codes live in
# _ISO2 and are matched case-sensitively so "IN" never fires on the word "in".
_COUNTRIES: Dict[str, List[str]] = {
    "New Zealand":   ["new zealand", "nzl", "aotearoa", "kiwi", "auckland",
                      "wellington", "christchurch", "hamilton nz", "dunedin", "queenstown"],
    "Australia":     ["australia", "aus", "australian", "sydney", "melbourne",
                      "brisbane", "perth", "adelaide", "canberra", "gold coast", "hobart"],
    "United States": ["united states", "usa", "u.s.a", "u.s.", "america", "american",
                      "new york", "nyc", "brooklyn", "los angeles", "san francisco",
                      "bay area", "silicon valley", "seattle", "chicago", "boston",
                      "austin", "denver", "portland", "atlanta", "miami", "houston",
                      "dallas", "phoenix", "philadelphia", "san diego", "san jose",
                      "washington dc", "las vegas", "detroit", "minneapolis"],
    "Canada":        ["canada", "can", "canadian", "toronto", "vancouver", "montreal",
                      "ottawa", "calgary", "edmonton", "quebec", "winnipeg"],
    "United Kingdom":["united kingdom", "great britain", "britain", "british", "gbr",
                      "england", "english", "scotland", "scottish", "wales", "welsh",
                      "northern ireland", "london", "manchester", "birmingham",
                      "glasgow", "edinburgh", "liverpool", "bristol", "leeds",
                      "cardiff", "belfast", "oxford", "cambridge uk"],
    "Ireland":       ["ireland", "irl", "irish", "dublin", "cork", "galway"],
    "Germany":       ["germany", "deutschland", "deu", "german", "berlin", "munich",
                      "münchen", "hamburg", "frankfurt", "cologne", "köln", "stuttgart"],
    "France":        ["france", "fra", "french", "paris", "lyon", "marseille",
                      "toulouse", "bordeaux", "nice france", "nantes"],
    "Spain":         ["spain", "españa", "esp", "spanish", "madrid", "barcelona",
                      "valencia", "seville", "sevilla", "bilbao", "malaga"],
    "Portugal":      ["portugal", "prt", "portuguese", "lisbon", "lisboa", "porto"],
    "Italy":         ["italy", "italia", "ita", "italian", "rome", "roma", "milan",
                      "milano", "naples", "turin", "florence", "venice"],
    "Netherlands":   ["netherlands", "holland", "nld", "dutch", "amsterdam",
                      "rotterdam", "utrecht", "eindhoven", "the hague"],
    "Belgium":       ["belgium", "bel", "belgian", "brussels", "antwerp", "ghent"],
    "Switzerland":   ["switzerland", "che", "swiss", "zurich", "zürich", "geneva",
                      "basel", "bern", "lausanne"],
    "Austria":       ["austria", "aut", "austrian", "vienna", "wien", "salzburg", "graz"],
    "Sweden":        ["sweden", "swe", "swedish", "sverige", "stockholm",
                      "gothenburg", "göteborg", "malmö"],
    "Norway":        ["norway", "nor", "norwegian", "norge", "oslo", "bergen", "trondheim"],
    "Denmark":       ["denmark", "dnk", "danish", "danmark", "copenhagen", "københavn", "aarhus"],
    "Finland":       ["finland", "fin", "finnish", "suomi", "helsinki", "tampere", "espoo"],
    "Iceland":       ["iceland", "isl", "icelandic", "reykjavik", "reykjavík"],
    "Poland":        ["poland", "pol", "polish", "polska", "warsaw", "warszawa",
                      "krakow", "kraków", "wroclaw", "gdansk", "poznan"],
    "Czechia":       ["czechia", "czech republic", "cze", "czech", "prague", "praha", "brno"],
    "Slovakia":      ["slovakia", "svk", "slovak", "bratislava", "kosice"],
    "Hungary":       ["hungary", "hun", "hungarian", "budapest", "debrecen"],
    "Romania":       ["romania", "rou", "romanian", "bucharest", "cluj", "timisoara"],
    "Bulgaria":      ["bulgaria", "bgr", "bulgarian", "sofia", "plovdiv", "varna"],
    "Greece":        ["greece", "grc", "greek", "athens", "thessaloniki", "hellas"],
    "Croatia":       ["croatia", "hrv", "croatian", "zagreb", "split croatia", "rijeka"],
    "Serbia":        ["serbia", "srb", "serbian", "belgrade", "novi sad"],
    "Ukraine":       ["ukraine", "ukr", "ukrainian", "kyiv", "kiev", "lviv",
                      "odesa", "odessa", "kharkiv", "dnipro"],
    "Russia":        ["russia", "rus", "russian", "moscow", "st petersburg",
                      "saint petersburg", "novosibirsk", "yekaterinburg", "kazan"],
    "Turkey":        ["turkey", "türkiye", "turkiye", "tur", "turkish", "istanbul",
                      "ankara", "izmir", "antalya", "bursa"],
    "India":         ["india", "ind", "indian", "bharat", "mumbai", "bombay", "delhi",
                      "new delhi", "bangalore", "bengaluru", "hyderabad", "chennai",
                      "kolkata", "pune", "ahmedabad", "jaipur", "kerala", "kochi",
                      "noida", "gurgaon", "gurugram", "chandigarh", "lucknow"],
    "Pakistan":      ["pakistan", "pak", "pakistani", "karachi", "lahore",
                      "islamabad", "rawalpindi", "faisalabad", "peshawar"],
    "Bangladesh":    ["bangladesh", "bgd", "bangladeshi", "dhaka", "chittagong", "sylhet"],
    "Sri Lanka":     ["sri lanka", "lka", "sri lankan", "colombo", "kandy", "jaffna"],
    "Nepal":         ["nepal", "npl", "nepali", "kathmandu", "pokhara"],
    "China":         ["china", "chn", "chinese", "beijing", "shanghai", "shenzhen",
                      "guangzhou", "hangzhou", "chengdu", "wuhan", "xian"],
    "Hong Kong":     ["hong kong", "hkg", "hongkong", "kowloon"],
    "Taiwan":        ["taiwan", "twn", "taiwanese", "taipei", "kaohsiung", "taichung"],
    "Japan":         ["japan", "jpn", "japanese", "nippon", "tokyo", "osaka", "kyoto",
                      "yokohama", "nagoya", "fukuoka", "sapporo", "kobe"],
    "South Korea":   ["south korea", "korea", "kor", "korean", "seoul", "busan",
                      "incheon", "daegu", "republic of korea"],
    "Singapore":     ["singapore", "sgp", "singaporean"],
    "Malaysia":      ["malaysia", "mys", "malaysian", "kuala lumpur", "penang", "johor"],
    "Indonesia":     ["indonesia", "idn", "indonesian", "jakarta", "bali", "surabaya",
                      "bandung", "medan", "yogyakarta"],
    "Thailand":      ["thailand", "tha", "thai", "bangkok", "chiang mai", "phuket"],
    "Vietnam":       ["vietnam", "viet nam", "vnm", "vietnamese", "hanoi",
                      "ho chi minh", "saigon", "da nang"],
    "Philippines":   ["philippines", "phl", "filipino", "philippine", "manila",
                      "cebu", "davao", "quezon city"],
    "United Arab Emirates": ["united arab emirates", "uae", "are", "emirati",
                             "dubai", "abu dhabi", "sharjah"],
    "Saudi Arabia":  ["saudi arabia", "sau", "saudi", "riyadh", "jeddah",
                      "mecca", "makkah", "medina", "dammam"],
    "Qatar":         ["qatar", "qat", "qatari", "doha"],
    "Kuwait":        ["kuwait", "kwt", "kuwaiti", "kuwait city"],
    "Bahrain":       ["bahrain", "bhr", "bahraini", "manama"],
    "Oman":          ["oman", "omn", "omani", "muscat"],
    "Israel":        ["israel", "isr", "israeli", "tel aviv", "jerusalem", "haifa"],
    "Jordan":        ["jordan", "jor", "jordanian", "amman"],
    "Lebanon":       ["lebanon", "lbn", "lebanese", "beirut"],
    "Iran":          ["iran", "irn", "iranian", "tehran", "isfahan", "mashhad"],
    "Iraq":          ["iraq", "irq", "iraqi", "baghdad", "basra", "erbil"],
    "Egypt":         ["egypt", "egy", "egyptian", "cairo", "alexandria", "giza"],
    "Morocco":       ["morocco", "mar", "moroccan", "casablanca", "rabat", "marrakech"],
    "Algeria":       ["algeria", "dza", "algerian", "algiers", "oran"],
    "Tunisia":       ["tunisia", "tun", "tunisian", "tunis"],
    "Nigeria":       ["nigeria", "nga", "nigerian", "lagos", "abuja", "ibadan",
                      "port harcourt", "kano"],
    "Ghana":         ["ghana", "gha", "ghanaian", "accra", "kumasi"],
    "Kenya":         ["kenya", "ken", "kenyan", "nairobi", "mombasa"],
    "Ethiopia":      ["ethiopia", "eth", "ethiopian", "addis ababa"],
    "Uganda":        ["uganda", "uga", "ugandan", "kampala"],
    "Tanzania":      ["tanzania", "tza", "tanzanian", "dar es salaam", "dodoma"],
    "South Africa":  ["south africa", "zaf", "south african", "johannesburg",
                      "cape town", "durban", "pretoria"],
    "Brazil":        ["brazil", "brasil", "bra", "brazilian", "sao paulo",
                      "são paulo", "rio de janeiro", "brasilia", "belo horizonte",
                      "curitiba", "porto alegre", "salvador"],
    "Argentina":     ["argentina", "arg", "argentine", "argentinian", "buenos aires",
                      "cordoba argentina", "rosario"],
    "Chile":         ["chile", "chl", "chilean", "santiago", "valparaiso"],
    "Colombia":      ["colombia", "col", "colombian", "bogota", "bogotá",
                      "medellin", "medellín", "cali"],
    "Peru":          ["peru", "per", "peruvian", "lima"],
    "Venezuela":     ["venezuela", "ven", "venezuelan", "caracas"],
    "Uruguay":       ["uruguay", "ury", "uruguayan", "montevideo"],
    "Ecuador":       ["ecuador", "ecu", "ecuadorian", "quito", "guayaquil"],
    "Bolivia":       ["bolivia", "bol", "bolivian", "la paz"],
    "Paraguay":      ["paraguay", "pry", "paraguayan", "asuncion"],
    "Mexico":        ["mexico", "méxico", "mex", "mexican", "mexico city",
                      "guadalajara", "monterrey", "cancun", "puebla", "tijuana"],
    "Costa Rica":    ["costa rica", "cri", "costa rican", "san jose costa rica"],
    "Panama":        ["panama", "pan", "panamanian", "panama city"],
    "Cuba":          ["cuba", "cub", "cuban", "havana"],
    "Dominican Republic": ["dominican republic", "dom", "dominican", "santo domingo"],
    "Jamaica":       ["jamaica", "jam", "jamaican", "kingston jamaica"],
    "Kazakhstan":    ["kazakhstan", "kaz", "kazakh", "almaty", "astana", "nur-sultan"],
    "Uzbekistan":    ["uzbekistan", "uzb", "uzbek", "tashkent"],
    "Azerbaijan":    ["azerbaijan", "aze", "azerbaijani", "baku"],
    "Georgia (country)": ["georgia country", "tbilisi", "georgian"],
    "Armenia":       ["armenia", "arm", "armenian", "yerevan"],
    "Belarus":       ["belarus", "blr", "belarusian", "minsk"],
    "Lithuania":     ["lithuania", "ltu", "lithuanian", "vilnius", "kaunas"],
    "Latvia":        ["latvia", "lva", "latvian", "riga"],
    "Estonia":       ["estonia", "est", "estonian", "tallinn", "tartu"],
    "Slovenia":      ["slovenia", "svn", "slovenian", "ljubljana"],
    "Luxembourg":    ["luxembourg", "lux", "luxembourgish"],
    "Malta":         ["malta", "mlt", "maltese", "valletta"],
    "Cyprus":        ["cyprus", "cyp", "cypriot", "nicosia", "limassol"],
}

# Two-letter ISO codes — matched only as standalone uppercase tokens.
_ISO2: Dict[str, str] = {
    "NZ": "New Zealand",   "AU": "Australia",      "US": "United States",
    "CA": "Canada",        "GB": "United Kingdom", "UK": "United Kingdom",
    "IE": "Ireland",       "DE": "Germany",        "FR": "France",
    "ES": "Spain",         "PT": "Portugal",       "IT": "Italy",
    "NL": "Netherlands",   "BE": "Belgium",        "CH": "Switzerland",
    "AT": "Austria",       "SE": "Sweden",         "NO": "Norway",
    "DK": "Denmark",       "FI": "Finland",        "IS": "Iceland",
    "PL": "Poland",        "CZ": "Czechia",        "SK": "Slovakia",
    "HU": "Hungary",       "RO": "Romania",        "BG": "Bulgaria",
    "GR": "Greece",        "HR": "Croatia",        "RS": "Serbia",
    "UA": "Ukraine",       "RU": "Russia",         "TR": "Turkey",
    "IN": "India",         "PK": "Pakistan",       "BD": "Bangladesh",
    "LK": "Sri Lanka",     "NP": "Nepal",          "CN": "China",
    "HK": "Hong Kong",     "TW": "Taiwan",         "JP": "Japan",
    "KR": "South Korea",   "SG": "Singapore",      "MY": "Malaysia",
    "ID": "Indonesia",     "TH": "Thailand",       "VN": "Vietnam",
    "PH": "Philippines",   "AE": "United Arab Emirates",
    "SA": "Saudi Arabia",  "QA": "Qatar",          "KW": "Kuwait",
    "BH": "Bahrain",       "OM": "Oman",           "IL": "Israel",
    "JO": "Jordan",        "LB": "Lebanon",        "IR": "Iran",
    "IQ": "Iraq",          "EG": "Egypt",          "MA": "Morocco",
    "DZ": "Algeria",       "TN": "Tunisia",        "NG": "Nigeria",
    "GH": "Ghana",         "KE": "Kenya",          "ET": "Ethiopia",
    "UG": "Uganda",        "TZ": "Tanzania",       "ZA": "South Africa",
    "BR": "Brazil",        "AR": "Argentina",      "CL": "Chile",
    "CO": "Colombia",      "PE": "Peru",           "VE": "Venezuela",
    "UY": "Uruguay",       "EC": "Ecuador",        "BO": "Bolivia",
    "PY": "Paraguay",      "MX": "Mexico",         "CR": "Costa Rica",
    "PA": "Panama",        "CU": "Cuba",           "DO": "Dominican Republic",
    "JM": "Jamaica",       "KZ": "Kazakhstan",     "UZ": "Uzbekistan",
    "AZ": "Azerbaijan",    "AM": "Armenia",        "BY": "Belarus",
    "LT": "Lithuania",     "LV": "Latvia",         "EE": "Estonia",
    "SI": "Slovenia",      "LU": "Luxembourg",     "MT": "Malta",
    "CY": "Cyprus",
}

# US state names/abbreviations all resolve to the United States.
_US_STATES = [
    "alabama","alaska","arizona","arkansas","california","colorado","connecticut",
    "delaware","florida","georgia","hawaii","idaho","illinois","indiana","iowa",
    "kansas","kentucky","louisiana","maine","maryland","massachusetts","michigan",
    "minnesota","mississippi","missouri","montana","nebraska","nevada",
    "new hampshire","new jersey","new mexico","north carolina","north dakota",
    "ohio","oklahoma","oregon","pennsylvania","rhode island","south carolina",
    "south dakota","tennessee","texas","utah","vermont","virginia","washington",
    "west virginia","wisconsin","wyoming",
]

# Longest aliases first so "new zealand" wins over a shorter overlapping alias.
_ALIAS_INDEX = sorted(
    (
        [(a, c) for c, aliases in _COUNTRIES.items() for a in aliases]
        + [(s, "United States") for s in _US_STATES]
    ),
    key=lambda pair: len(pair[0]),
    reverse=True,
)

_ALIAS_PATTERNS = [
    (re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", re.IGNORECASE), country)
    for alias, country in _ALIAS_INDEX
]

_ISO2_PATTERNS = [
    (re.compile(rf"(?<![A-Za-z0-9]){code}(?![A-Za-z0-9])"), country)
    for code, country in _ISO2.items()
]


def resolve_countries(text: str) -> Set[str]:
    """Canonical countries named in a short location string. Empty when unreadable."""
    if not text:
        return set()
    found: Set[str] = set()
    for pattern, country in _ALIAS_PATTERNS:
        if pattern.search(text):
            found.add(country)
    for pattern, country in _ISO2_PATTERNS:
        if pattern.search(text):
            found.add(country)
    return found


def describe_subject_location(raw: str) -> str:
    """Human-readable echo of what Helix understood the subject's location to be."""
    countries = resolve_countries(raw)
    if not countries:
        return f"{raw} (unrecognised — conflict checks disabled)"
    return f"{raw} → {', '.join(sorted(countries))}"


# ── Explicit location markers in profile HTML ────────────────────────────────
# Only these patterns are trusted. A bare country name elsewhere on a page is
# never treated as a claim about the account holder.
_HINT_PATTERNS = [
    re.compile(r'"location"\s*:\s*"([^"]{2,60})"', re.IGNORECASE),
    re.compile(r'"addressLocality"\s*:\s*"([^"]{2,60})"', re.IGNORECASE),
    re.compile(r'"homeLocation"\s*:\s*"([^"]{2,60})"', re.IGNORECASE),
    re.compile(r'<meta[^>]+(?:name|property)=["\'](?:geo\.placename|profile:location|business:contact_data:locality)["\'][^>]+content=["\']([^"\']{2,60})["\']', re.IGNORECASE),
    re.compile(r'itemprop=["\']homeLocation["\'][^>]*>\s*([^<]{2,60})<', re.IGNORECASE),
    re.compile(r'class=["\'][^"\']*\blocation\b[^"\']*["\'][^>]*>\s*([^<]{2,60})<', re.IGNORECASE),
    re.compile(r'\bLocation\s*[:：]\s*([A-Za-z][^<>\n|,;]{1,50})', re.IGNORECASE),
    re.compile(r'\b(?:based|lives|living|located)\s+in\s+([A-Za-z][^<>\n|,;.]{1,50})', re.IGNORECASE),
    re.compile(r'📍\s*([A-Za-z][^<>\n|,;]{1,50})'),
]

_HINT_NOISE = re.compile(
    r"(https?:|www\.|\{|\}|\bnull\b|\bundefined\b|\bN/?A\b|^\s*-?\s*$)", re.IGNORECASE
)


def extract_location_hints(html: str, limit: int = 6) -> List[str]:
    """Location strings a page explicitly asserts about its subject."""
    if not html:
        return []
    hints: List[str] = []
    seen: Set[str] = set()
    for pattern in _HINT_PATTERNS:
        for match in pattern.finditer(html):
            raw = " ".join(match.group(1).split()).strip(" \t-–—·,")
            if not raw or len(raw) < 2 or _HINT_NOISE.search(raw):
                continue
            key = raw.lower()
            if key in seen:
                continue
            seen.add(key)
            hints.append(raw)
            if len(hints) >= limit:
                return hints
    return hints


def annotate_locations(results: List[dict]) -> None:
    """
    Record each found result's asserted location. Runs before sanitisation,
    while the raw page text is still attached, and persists only the short
    extracted strings.
    """
    for r in results:
        if not r.get("found"):
            continue
        text  = (r.get("_page_text") or "") + "\n" + (r.get("og_title") or "")
        hints = extract_location_hints(text)
        if hints:
            r["location_hints"] = hints
            countries = set()
            for h in hints:
                countries |= resolve_countries(h)
            r["location_countries"] = sorted(countries)


def flag_conflicts(results: List[dict], subject_location: str) -> List[dict]:
    """
    Flag found profiles whose stated location cannot be reconciled with the
    subject's known location. Conflicting profiles are never purged — they are
    downgraded and surfaced so the investigator decides.

    Returns one entry per conflicting profile.
    """
    subject = resolve_countries(subject_location or "")
    if not subject:
        return []

    conflicts = []
    for r in results:
        if not r.get("found"):
            continue
        stated = set(r.get("location_countries") or [])
        if not stated or stated & subject:
            continue

        r["location_conflict"] = True
        r["location_note"] = (
            f"profile states {', '.join(sorted(stated))} — "
            f"subject is known to be in {', '.join(sorted(subject))}"
        )
        if r.get("confidence") == "high":
            r["confidence"] = "medium"
        conflicts.append({
            "platform": r.get("platform", ""),
            "url":      r.get("url", ""),
            "stated":   sorted(stated),
            "expected": sorted(subject),
            "hints":    r.get("location_hints", []),
        })
    return conflicts
