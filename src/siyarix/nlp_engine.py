# SPDX-License-Identifier: AGPL-3.0-or-later
"""Natural Language Processing Engine for Offline Heuristic Planning.

Provides advanced intent scoring, entity extraction, and semantic
parameter extraction without heavy machine learning dependencies.
"""

from __future__ import annotations

import re
import math
import difflib
from dataclasses import dataclass, field
from typing import Any, Set


@dataclass
class ParsedIntent:
    target: str = ""
    target_type: str = ""  # e.g., 'url', 'ip', 'domain'
    tool_name: str | None = None
    template_name: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    tokens: list[str] = field(default_factory=list)


class NaturalLanguageParser:
    """A lightweight, zero-dependency NLP engine for intent mapping."""

    # Common English stopwords to filter out noise
    STOPWORDS: Set[str] = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "but",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "up",
        "about",
        "into",
        "over",
        "after",
        "please",
        "can",
        "you",
        "do",
        "i",
        "want",
        "need",
        "could",
        "would",
        "run",
        "execute",
        "perform",
        "start",
        "initiate",
        "make",
        "give",
        "me",
    }

    # Regex patterns for Entity Extraction
    PATTERNS = {
        "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
        "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    }

    # Suffixes for lightweight stemming
    SUFFIXES = ["ing", "ed", "s", "es", "ly", "tion", "ity"]

    # Default Synonyms (can be customized by user config later)
    DEFAULT_SYNONYMS = {
        "bug": "vuln",
        "cve": "vuln",
        "exploit": "vuln",
        "hack": "vuln",
        "dirbust": "directory",
        "enum": "enumeration",
        "subdomain": "recon",
        "passwords": "brute",
        "creds": "brute",
        "sql": "sqli",
    }

    def __init__(self, custom_synonyms: dict[str, str] | None = None) -> None:
        self._tool_corpus: dict[str, list[str]] = {}
        self._template_corpus: dict[str, list[str]] = {}
        self.synonyms = self.DEFAULT_SYNONYMS.copy()
        if custom_synonyms:
            self.synonyms.update(custom_synonyms)

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

    def train_templates(self, templates_metadata: dict[str, str]) -> None:
        """Feed workflow templates to the parser."""
        for name, desc in templates_metadata.items():
            text = f"{name.replace('_', ' ')} {desc}".lower()
            self._template_corpus[name] = self.tokenize(text)

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
        """Extract the primary target (URL, IP, or Domain)."""
        # Try URL first
        urls = re.findall(self.PATTERNS["url"], text)
        if urls:
            return urls[0], "url"

        # Try IPv4
        ips = re.findall(self.PATTERNS["ipv4"], text)
        if ips:
            return ips[0], "ipv4"

        # Try Domain
        domains = re.findall(self.PATTERNS["domain"], text)
        # Filter out false positives like "e.g." or "v.1"
        valid_domains = [d for d in domains if len(d) > 4]
        if valid_domains:
            return valid_domains[0], "domain"

        return "", ""

    def extract_parameters(self, text: str) -> dict[str, str]:
        """Extract modifier arguments (speed, ports, stealth, time, format, severity)."""
        params = {}
        text_lower = text.lower()

        # Port extraction
        port_match = re.search(r"\bport(?:s)?\s*([0-9,\-]+)\b", text_lower)
        if port_match:
            params["ports"] = port_match.group(1)
        elif "all ports" in text_lower or "full ports" in text_lower:
            params["ports"] = "all"

        # Speed extraction
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
        if "critical" in text_lower and "high" in text_lower:
            params["severity"] = "critical,high"
        elif "critical" in text_lower:
            params["severity"] = "critical"
        elif "high" in text_lower:
            params["severity"] = "high"
        elif "medium" in text_lower:
            params["severity"] = "medium"

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

        # Output extraction
        if any(word in text_lower for word in ["verbose", "detail"]):
            params["verbose"] = "true"

        return params

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
        """Calculate Term Frequency similarity to find the best match."""
        best_match = None
        highest_score = 0.0

        for name, doc_tokens in corpus.items():
            score = 0.0
            # BM25-style intersection scoring with fuzzy tolerance
            for token in tokens:
                if "_" in token:
                    # N-grams are weighted heavily
                    if token in doc_tokens:
                        score += 3.0
                elif self.fuzzy_match(token, doc_tokens):
                    # Weight exact name matches extremely high
                    if token == name:
                        score += 5.0
                    else:
                        score += 1.0

            # Normalize by document length to prevent long docs from always winning
            if doc_tokens:
                score = score / math.sqrt(len(doc_tokens))

            if score > highest_score:
                highest_score = score
                best_match = name

        return best_match, highest_score

    def parse(self, text: str) -> ParsedIntent:
        """Parse natural language into a structured intent."""
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

            # Templates usually capture complex intents better, slightly favor them
            if tpl_score > 0 and (tpl_score * 1.2) >= tool_score:
                intent.template_name = tpl_match
                intent.confidence = tpl_score
            elif tool_score > 0:
                intent.tool_name = tool_match
                intent.confidence = tool_score

        return intent
