from __future__ import annotations

import re

UNSAFE_REQUEST_RE = re.compile(
    r"\b(working exploit|write (?:a )?exploit|exploit for|exploit code|payload|intrusion|credential theft|"
    r"evad(?:e|ing)|unauthori[sz]ed access|print (?:the )?system prompt|"
    r"reveal (?:the )?system prompt|ignore all previous instructions)\b",
    re.IGNORECASE,
)

IRRELEVANT_TOPIC_RE = re.compile(
    r"\b("
    r"who won(?:\s+(?:the\s+)?(?:\d{4}\s+)?(?:us\s+)?election)?|"
    r"who is the president|who was the president|who is the prime minister|who won the match|"
    r"election|presidential election|prime minister|congress|senate|parliament|democrat|republican|"
    r"biden|trump|obama|modi|putin|kamala|voting|ballot|"
    r"movie|cinema|actor|actress|box office|song|music|album|singer|celebrity|hollywood|bollywood|netflix|"
    r"cricket|football|soccer|fifa|super bowl|nba|nfl|world cup|olympics|"
    r"recipe|how to cook|how to make (?:pizza|coffee|tea|cake|bread)|pizza|burger|cake|diet|horoscope|zodiac|dating advice|relationship advice|tell me a joke|"
    r"write (?:a )?poem|write (?:a )?story|write (?:an )?essay|essay on|solve (?:this )?math|fibonacci|bubble sort|homework|do my homework|"
    r"stock price|bitcoin price|crypto price|crypto prediction|buy shares|invest in stocks|"
    r"capital of|tallest mountain|highest peak|population of|distance between|weather in|weather forecast"
    r")\b",
    re.IGNORECASE,
)


def refusal_reason(query: str) -> str | None:
    if UNSAFE_REQUEST_RE.search(query):
        return (
            "I cannot provide exploit instructions or hidden system prompts. "
            "I can help with a defensive CVE investigation."
        )
    if IRRELEVANT_TOPIC_RE.search(query):
        return (
            "I can only assist with defensive cybersecurity vulnerability investigations. "
            "Off-topic requests (such as politics, elections, general trivia, entertainment, or non-security inquiries) "
            "are outside my operational scope."
        )
    return None
