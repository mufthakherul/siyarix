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
        "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "mac": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
    }

    # Suffixes for lightweight stemming
    SUFFIXES = ["ing", "ed", "s", "es", "ly", "tion", "ity", "ment", "ness", "able", "ible"]

    # Default Synonyms mapped to canonical terms
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
        """Extract modifier arguments (speed, ports, stealth, time, format, severity, wordlist)."""
        params = {}
        text_lower = text.lower()

        # Port extraction
        port_match = re.search(r"\bport(?:s)?\s*([0-9,\-]+)\b", text_lower)
        if port_match:
            params["ports"] = port_match.group(1)
        elif "all ports" in text_lower or "full ports" in text_lower:
            params["ports"] = "all"

        # Speed / Stealth extraction
        if any(word in text_lower for word in ["fast", "quick", "speedy", "rapid"]):
            params["speed"] = "fast"
        elif any(word in text_lower for word in ["stealth", "slow", "sneaky", "quiet", "evasive"]):
            params["speed"] = "stealth"
        elif any(word in text_lower for word in ["aggressive", "intense", "heavy"]):
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
            params["protocol"] = "udp"
        elif "tcp" in text_lower:
            params["protocol"] = "tcp"

        # Output verbosity
        if any(word in text_lower for word in ["verbose", "detail", "detailed"]):
            params["verbose"] = "true"
            
        # Wordlist extraction
        wordlist_match = re.search(r"\bwordlist\s*([a-zA-Z0-9_./\-]+)\b", text_lower)
        if wordlist_match:
            params["wordlist"] = wordlist_match.group(1)

        return params

    def get_idf(self, token: str) -> float:
        """Calculate Inverse Document Frequency for a token."""
        df = self._doc_frequencies.get(token, 0)
        if df == 0 or self._total_docs == 0:
            return 1.0  # Unknown words have high IDF
        return math.log(self._total_docs / (1 + df)) + 1.0

    def fuzzy_match(self, token: str, corpus_tokens: list[str]) -> bool:
        """Check if a token fuzzy-matches any corpus token using difflib."""
        if not corpus_tokens:
            return False
        # Only fuzzy match longer words to avoid false positives on small words
        if len(token) < 5:
            return token in corpus_tokens

        # Find closest match
        matches = difflib.get_close_matches(token, corpus_tokens, n=1, cutoff=0.75)
        return len(matches) > 0

    def score_intent(
        self, tokens: list[str], corpus: dict[str, list[str]]
    ) -> tuple[str | None, float]:
        """Calculate TF-IDF style similarity to find the best matching intent."""
        best_match = None
        highest_score = 0.0

        for name, doc_tokens in corpus.items():
            score = 0.0
            
            # Count term frequencies in the document
            doc_tf: dict[str, int] = defaultdict(int)
            for t in doc_tokens:
                doc_tf[t] += 1

            for token in tokens:
                idf = self.get_idf(token)
                
                if "_" in token:
                    # N-grams are weighted heavily
                    if token in doc_tokens:
                        score += 3.0 * idf
                elif self.fuzzy_match(token, doc_tokens):
                    # Weight exact name matches extremely high
                    if token == name:
                        score += 6.0 * idf
                    else:
                        score += 1.0 * idf * doc_tf.get(token, 1)

            # Normalize by document length penalty to prevent long docs from always winning
            if doc_tokens:
                score = score / math.pow(len(doc_tokens), 0.5)

            if score > highest_score:
                highest_score = score
                best_match = name

        return best_match, highest_score

    def parse(self, text: str) -> ParsedIntent:
        """Parse natural language into a structured intent representation."""
        intent = ParsedIntent()

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

        return intent

