"""
tools/explain.py

Explanation tool for Agentic Maliciousness Query Agent.
Provides:
- def compose_explanation(
    *,
    data: dict,
    score: float
) -> str:

You may call it with a single JSON payload or with named arguments.
"""
import os
from langchain.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage

# Initialize LangChain ChatOpenAI (hard-code key here for now)
_llm = ChatOpenAI(
    model_name="gpt-3.5-turbo",
    temperature=0,
    openai_api_key=os.getenv("OPENAI_API_KEY")
)

def compose_explanation(
    *args,
    data: dict = None,
    score: float = None
) -> str:
    """
    Generate a natural-language explanation.
      - Positional: first arg may be the `data` dict.
      - Keyword: `score` must be supplied either way.
    """
    # 1) If we got a positional dict, treat it as `data`
    if args and data is None and isinstance(args[0], dict):
        data = args[0]

    # 2) Ensure data is a dict and score is a float
    data = data or {}
    score = score if score is not None else 0.0

    # 3) Safely extract sub-components
    whois = data.get("whois") or {}
    geoip = data.get("geoip") or {}
    feed  = data.get("threat_feed") or {}

    # 4) Build the prompt
    prompt = (
        "You are a cybersecurity analyst. Given the following intelligence and a risk score, "
        "provide a concise justification and state whether the target is likely malicious."
        f"\n\nScore: {score}\n"
        f"WHOIS: {whois}\n"
        f"GeoIP: {geoip}\n"
        f"Threat Feed: {feed}"
    )
    messages = [
        SystemMessage(content="You analyze threat intelligence and explain risk."),
        HumanMessage(content=prompt)
    ]
    response = _llm(messages)
    return response.content.strip()


if __name__ == "__main__":
    # Quick test harness
    from tools.fetch import fetch_whois, geoip_lookup, fetch_threat_feed, IPV4_PATTERN
    from tools.score import score_target

    for target in ["example.com", "8.8.8.8"]:
        whois = fetch_whois(target)
        geoip = geoip_lookup(target) if IPV4_PATTERN.match(target) else None
        feed = fetch_threat_feed(target).get("threat_feed")
        score = score_target({"whois": whois, "geoip": geoip, "threat_feed": feed})
        # Positional-call style
        print(">>> Positional:", compose_explanation({"whois": whois, "geoip": geoip, "threat_feed": feed}, score=score))
        # Keyword call style
        print("<<< Keyword:   ", compose_explanation(data={"whois": whois, "geoip": geoip, "threat_feed": feed}, score=score))