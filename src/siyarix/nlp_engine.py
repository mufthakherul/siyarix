# SPDX-License-Identifier: AGPL-3.0-or-later
"""Natural Language Processing Engine for Offline Heuristic Planning.

Provides advanced intent scoring, entity extraction, semantic parameter
extraction, and TF-IDF based keyword weighting without heavy machine learning dependencies.
"""

from __future__ import annotations

import re
import math
import difflib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedIntent:
    target: str = ""
    target_type: str = ""  # e.g., 'url', 'ipv4', 'domain', 'email', 'mac'
    tool_name: str | None = None
    template_name: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    tokens: list[str] = field(default_factory=list)
    raw_text: str = ""


class NaturalLanguageParser:
    """An advanced, zero-dependency NLP engine for intent mapping and semantic parsing."""

    # Comprehensive English stopwords to filter out noise
    STOPWORDS: frozenset[str] = frozenset(
        {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "by", "from", "up", "about", "into", "over", "after",
            "please", "can", "you", "do", "i", "want", "need", "could", "would",
            "run", "execute", "perform", "start", "initiate", "make", "give", "me",
            "show", "find", "get", "tell", "is", "are", "was", "were", "be", "been",
            "have", "has", "had", "what", "which", "who", "where", "why", "how",
            "all", "any", "some", "every", "just", "now", "then", "like",
        }
    )

    # Regex patterns for Entity Extraction
    PATTERNS = {
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
        "aws_s3": r"\b(?:[a-zA-Z0-9.\-_]{3,63}\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)\b",
        "azure_blob": r"\b(?:[a-z0-9]{3,24}\.blob\.core\.windows\.net)\b",
        "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
        "cidr": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-2]?[0-9]|3[0-2])\b",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "mac": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
        "sha256": r"\b[A-Fa-f0-9]{64}\b",
        "sha1": r"\b[A-Fa-f0-9]{40}\b",
        "md5": r"\b[A-Fa-f0-9]{32}\b",
        "asn": r"\bAS\d{1,6}\b",
        "windows_path": r"\b[a-zA-Z]:\\[^:\*\?\"<>\|\s]+\b",
        "linux_path": r"(?<!\w)(?:/[a-zA-Z0-9_\-\.]+)+\b",
        "github_repo": r"\b(?:https?://github\.com/)?(?:[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)\b",
        "ntlm": r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b",
        "gcp_bucket": r"\b(?:[a-z0-9\-_]{3,63}\.storage\.googleapis\.com)\b",
    }

    # Suffixes for lightweight stemming
    SUFFIXES = ["ing", "ed", "s", "es", "ly", "tion", "ity", "ment", "ness", "able", "ible"]

    # Extended Ontology mapping synonyms to canonical forms (including MITRE tactics)
    DEFAULT_SYNONYMS = {
        "bug": "vuln",
        "cve": "vuln",
        "exploit": "vuln",
        "hack": "vuln",
        "weakness": "vuln",
        "flaw": "vuln",
        "dirbust": "directory",
        "enum": "enumeration",
        "discover": "recon",
        "subdomain": "recon",
        "passwords": "brute",
        "creds": "brute",
        "credentials": "brute",
        "sql": "sqli",
        "injection": "sqli",
        "xss": "cross-site",
        "mitm": "intercept",
        "sniff": "intercept",
        "phish": "social",
        # MITRE ATT&CK & Advanced Slang mappings
        "reconnaissance": "recon",
        "weaponize": "exploit",
        "delivery": "phish",
        "lateral": "pivoting",
        "movement": "pivoting",
        "exfiltration": "exfil",
        "dump": "brute",
        "hashdump": "brute",
        "privesc": "escalation",
        "osint": "recon",
        "fuzz": "fuzzing",
        "dos": "denial",
        "ddos": "denial",
        "sam": "credentials",
        "ntds": "credentials",
        "lsass": "credentials",
        "rce": "exploit",
        "shell": "exploit",
        "root": "escalation",
        "system": "escalation",
        "smb": "smb",
        "rdp": "rdp",
        "ssh": "ssh",
        "ftp": "ftp",
        "dns": "dns",
        "header": "headers",
        "tech": "technology",
        "os": "operating_system",
        "mail": "email",
        "mx": "dns",
        "txt": "dns",
        "soa": "dns",
        "api": "endpoint",
        "rest": "endpoint",
        "container": "docker",
        "kubernetes": "k8s",
        "kube": "k8s",
        "waf": "firewall",
        "proxy": "network",
        "vpn": "network",
        "firewall": "acl",
        "acl": "acl",
        "cert": "tls",
        "certificate": "tls",
        "cloudfront": "cdn",
        "cdn": "cdn",
        "loadbalancer": "lb",
        "git": "vcs",
        "jenkins": "ci",
        "ci": "ci",
        "jira": "ticket",
        "confluence": "wiki",
        "ldap": "ldap",
        "ntlm": "ntlm",
        "kerberos": "kerberos",
        "ad": "activedirectory",
    }

    def __init__(self, custom_synonyms: dict[str, str] | None = None) -> None:
        self._tool_corpus: dict[str, list[str]] = {}
        self._template_corpus: dict[str, list[str]] = {}
        
        # IDF (Inverse Document Frequency) components
        self._doc_frequencies: dict[str, int] = defaultdict(int)
        self._total_docs: int = 0
        
        self.synonyms = self.DEFAULT_SYNONYMS.copy()
        if custom_synonyms:
            self.synonyms.update(custom_synonyms)

    def _recalculate_idf(self) -> None:
        """Calculate document frequencies for IDF weighting."""
        self._doc_frequencies.clear()
        self._total_docs = len(self._tool_corpus) + len(self._template_corpus)
        
        for tokens in self._tool_corpus.values():
            for t in set(tokens):
                self._doc_frequencies[t] += 1
                
        for tokens in self._template_corpus.values():
            for t in set(tokens):
                self._doc_frequencies[t] += 1

    def train_tools(self, tools_metadata: list[dict[str, Any]]) -> None:
        """Feed tool descriptions to the parser to build semantic corpus."""
        for t in tools_metadata:
            name = t.get("name", "")
            desc = t.get("description", "")
            tags = " ".join(t.get("tags", []))
            category = str(t.get("category", ""))
            # Combine all semantic clues
            text = f"{name} {desc} {tags} {category}".lower()
            self._tool_corpus[name] = self.tokenize(text)
        self._recalculate_idf()

    def train_templates(self, templates_metadata: dict[str, str]) -> None:
        """Feed workflow templates to the parser."""
        for name, desc in templates_metadata.items():
            text = f"{name.replace('_', ' ')} {desc}".lower()
            self._template_corpus[name] = self.tokenize(text)
        self._recalculate_idf()

    def stem_word(self, word: str) -> str:
        """Lightweight Porter-style suffix stripping."""
        for suffix in self.SUFFIXES:
            if word.endswith(suffix) and len(word) - len(suffix) >= 3:
                stem = word[: -len(suffix)]
                if len(stem) > 2 and stem[-1] == stem[-2]:
                    return stem[:-1]
                return stem
        return word

    def tokenize(self, text: str) -> list[str]:
        """Convert raw text into normalized semantic tokens including N-Grams."""
        text = text.lower()
        # Remove punctuation except hyphens
        text = re.sub(r"[^\w\s-]", " ", text)
        words = text.split()

        tokens = []
        clean_words = []
        for w in words:
            if w and w not in self.STOPWORDS and len(w) > 1:
                # Apply stemming first
                stemmed = self.stem_word(w)
                # Apply synonym mapping
                mapped = self.synonyms.get(stemmed, stemmed)
                clean_words.append(mapped)
                tokens.append(mapped)

        # Generate Bigrams
        for i in range(len(clean_words) - 1):
            tokens.append(f"{clean_words[i]}_{clean_words[i + 1]}")

        # Generate Trigrams
        for i in range(len(clean_words) - 2):
            tokens.append(f"{clean_words[i]}_{clean_words[i + 1]}_{clean_words[i + 2]}")

        return tokens

    def extract_entities(self, text: str) -> tuple[str, str]:
        """Extract the primary target (URL, IP, Domain, Email, MAC)."""
        # Iterate over patterns in priority order
        for entity_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                # For domains, filter out false positives like "e.g." or "v.1"
                if entity_type == "domain":
                    valid_matches = [m for m in matches if len(m) > 4 and not m.startswith("e.g")]
                    if valid_matches:
                        return valid_matches[0], entity_type
                else:
                    return matches[0], entity_type

        return "", ""

    def extract_parameters(self, text: str) -> dict[str, str]:
        """Extract modifier arguments with Negation Context Handling."""
        params = {}
        text_lower = text.lower()
        
        # Check for global negations in the context
        is_negated = any(neg in text_lower for neg in ["not ", "no ", "without ", "skip ", "exclude "])

        # Port extraction
        port_match = re.search(r"\bport(?:s)?\s*([0-9,\-]+)\b", text_lower)
        if port_match:
            params["ports"] = port_match.group(1)
        elif "all ports" in text_lower or "full ports" in text_lower:
            params["ports"] = "all"

        # Speed / Stealth extraction (Negation Aware)
        is_fast = any(word in text_lower for word in ["fast", "quick", "speedy", "rapid"])
        is_stealth = any(word in text_lower for word in ["stealth", "slow", "sneaky", "quiet", "evasive"])
        is_aggressive = any(word in text_lower for word in ["aggressive", "intense", "heavy"])

        if is_negated:
            if is_fast or is_aggressive:
                params["speed"] = "stealth"
            elif is_stealth:
                params["speed"] = "fast"
        else:
            if is_fast:
                params["speed"] = "fast"
            elif is_stealth:
                params["speed"] = "stealth"
            elif is_aggressive:
                params["speed"] = "aggressive"

        # Time / Duration extraction
        time_match = re.search(r"\b(?:timeout|max time|run for)\s*(\d+[smhd])\b", text_lower)
        if time_match:
            params["timeout"] = time_match.group(1)

        # Severity extraction (for vuln scanners)
        severities = []
        if "critical" in text_lower:
            severities.append("critical")
        if "high" in text_lower:
            severities.append("high")
        if "medium" in text_lower:
            severities.append("medium")
        if "low" in text_lower:
            severities.append("low")
        if severities:
            if is_negated and "low" in severities:
                params["severity"] = "high,critical"
            else:
                params["severity"] = ",".join(severities)

        # Output Format extraction
        if "json" in text_lower:
            params["format"] = "json"
        elif "xml" in text_lower:
            params["format"] = "xml"
        elif "markdown" in text_lower or " md " in text_lower:
            params["format"] = "markdown"

        # Protocol extraction
        if "udp" in text_lower:
            params["protocol"] = "tcp" if is_negated else "udp"
        elif "tcp" in text_lower:
            params["protocol"] = "udp" if is_negated else "tcp"

        # Output verbosity
        if any(word in text_lower for word in ["verbose", "detail", "detailed"]):
            if not is_negated:
                params["verbose"] = "true"
            
        # Wordlist extraction
        wordlist_match = re.search(r"\bwordlist\s*([a-zA-Z0-9_./\-]+)\b", text_lower)
        if wordlist_match:
            params["wordlist"] = wordlist_match.group(1)

        # Concurrency / Threads extraction
        threads_match = re.search(r"\b(?:threads|rate|connections|workers)\s*(\d+)\b", text_lower)
        if threads_match:
            params["threads"] = threads_match.group(1)

        # Auth extraction (Username / Password)
        user_match = re.search(r"\b(?:user|username)\s+([a-zA-Z0-9_.\-]+)\b", text_lower)
        if user_match:
            params["username"] = user_match.group(1)
            
        pass_match = re.search(r"\b(?:pass|password)\s+([a-zA-Z0-9_.\-!@#$%^&*]+)\b", text_lower)
        if pass_match:
            params["password"] = pass_match.group(1)

        # Module / Plugin extraction
        module_match = re.search(r"\b(?:module|plugin|script)\s+([a-zA-Z0-9_.\-]+)\b", text_lower)
        if module_match:
            params["module"] = module_match.group(1)

        return params

    def get_idf(self, token: str) -> float:
        """Calculate Inverse Document Frequency for a token."""
        df = self._doc_frequencies.get(token, 0)
        if df == 0 or self._total_docs == 0:
            return 1.0  # Unknown words have high IDF
        return math.log(self._total_docs / (1 + df)) + 1.0

    def _phonetic_simplify(self, word: str) -> str:
        """Lightweight phonetic normalizer for cybersecurity typos."""
        w = word.lower()
        # Remove consecutive duplicates (e.g. 'ffuf' -> 'fuf', 'dirbuster' -> 'dirbuster')
        w = re.sub(r'(.)\1+', r'\1', w)
        # Basic phonetic substitutions
        w = w.replace('ph', 'f').replace('y', 'i').replace('c', 'k')
        return w

    def _get_char_bigrams(self, word: str) -> set[str]:
        if len(word) < 2:
            return {word}
        return set(word[i:i+2] for i in range(len(word)-1))

    def fuzzy_match(self, token: str, corpus_tokens: list[str]) -> bool:
        """Check if a token fuzzy-matches any corpus token using Jaccard N-Gram similarity."""
        if not corpus_tokens:
            return False
        if len(token) < 5:
            return token in corpus_tokens

        token_phonetic = self._phonetic_simplify(token)
        token_bigrams = self._get_char_bigrams(token_phonetic)

        for c_token in corpus_tokens:
            if len(c_token) < 5:
                if token == c_token:
                    return True
                continue
                
            # Fast difflib check for transpositions (like direcotry -> directory)
            if difflib.get_close_matches(token, [c_token], n=1, cutoff=0.75):
                return True

            c_token_phonetic = self._phonetic_simplify(c_token)
            c_bigrams = self._get_char_bigrams(c_token_phonetic)
            
            # Calculate Jaccard similarity for phonetic replacements
            intersection = len(token_bigrams.intersection(c_bigrams))
            union = len(token_bigrams.union(c_bigrams))
            if union == 0:
                continue
                
            similarity = intersection / union
            if similarity >= 0.50:  # 50% overlap in phonetic bigrams is robust for typos
                return True

        return False

    def score_intent(
        self, tokens: list[str], corpus: dict[str, list[str]]
    ) -> tuple[str | None, float]:
        """Calculate Okapi BM25 similarity to find the best matching intent.
        
        BM25 improves upon TF-IDF by capping term frequency saturation and properly
        normalizing based on average document length, making it the industry standard
        for information retrieval.
        """
        best_match = None
        highest_score = 0.0

        # Calculate average document length for BM25
        avgdl = sum(len(doc) for doc in corpus.values()) / max(1, len(corpus))
        k1 = 1.5  # Term frequency saturation parameter
        b = 0.75  # Length normalization parameter

        for name, doc_tokens in corpus.items():
            score = 0.0
            doc_len = len(doc_tokens)
            
            # Count term frequencies in the document
            doc_tf: dict[str, int] = defaultdict(int)
            for t in doc_tokens:
                doc_tf[t] += 1

            for token in tokens:
                idf = self.get_idf(token)
                term_freq = 0
                
                if "_" in token:
                    # N-grams
                    if token in doc_tokens:
                        term_freq = 3  # Boost N-gram matches
                elif self.fuzzy_match(token, doc_tokens):
                    if token == name:
                        term_freq = 6  # Huge boost for exact name match
                    else:
                        term_freq = doc_tf.get(token, 1)

                if term_freq > 0:
                    # Okapi BM25 scoring formula
                    numerator = term_freq * (k1 + 1)
                    denominator = term_freq + k1 * (1 - b + b * (doc_len / max(1.0, avgdl)))
                    score += idf * (numerator / denominator)

            if score > highest_score:
                highest_score = score
                best_match = name

        return best_match, highest_score

    def parse(self, text: str) -> ParsedIntent:
        """Parse natural language into a structured intent representation."""
        intent = ParsedIntent(raw_text=text)

        # 1. Target Extraction
        intent.target, intent.target_type = self.extract_entities(text)

        # Strip the target from text to prevent it from confusing intent matching
        clean_text = text.replace(intent.target, "") if intent.target else text

        # 2. Tokenization
        intent.tokens = self.tokenize(clean_text)

        # 3. Parameter Extraction
        intent.parameters = self.extract_parameters(clean_text)

        # 4. Intent Scoring
        if intent.tokens:
            tpl_match, tpl_score = self.score_intent(intent.tokens, self._template_corpus)
            tool_match, tool_score = self.score_intent(intent.tokens, self._tool_corpus)

            # Templates usually capture complex intents better, slightly favor them (+20% bonus)
            if tpl_score > 0 and (tpl_score * 1.2) >= tool_score:
                intent.template_name = tpl_match
                intent.confidence = tpl_score
            elif tool_score > 0:
                intent.tool_name = tool_match
                intent.confidence = tool_score

        # Minimum confidence threshold — garbled/unrecognised input drops to None
        if intent.confidence < 0.15:
            intent.tool_name = None
            intent.template_name = None
            intent.confidence = 0.0

        return intent

    def parse_multi(self, text: str) -> list[ParsedIntent]:
        """Parse natural language into multiple structured intents if conjunctions exist."""
        # Split text by unambiguous multi-step conjunctions
        split_pattern = r"\b(?:and then|followed by|&&|,\s*then)\b"
        parts = re.split(split_pattern, text, flags=re.IGNORECASE)
        
        intents = []
        for part in parts:
            part = part.strip()
            if len(part) > 3:
                intents.append(self.parse(part))
        return intents

