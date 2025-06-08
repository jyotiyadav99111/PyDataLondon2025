"""
tools/score.py

Scoring logic for Agentic Maliciousness Query Agent.
Contains:
- score_target(data: dict) -> float

Scoring combines WHOIS age, GeoIP risk, and threat feed stats into a 0–10 risk score.
Includes a simple test harness when run as __main__.
"""
import datetime

# Configuration: weights for each component
WEIGHTS = {
    'age_days': 0.3,    # newer domains get higher risk
    'geo_risk': 0.2,    # risk based on GeoIP location
    'threat_hits': 0.5  # malicious hits weight
}

# Age score thresholds
AGE_THRESHOLDS = {
    '0-30': 10,
    '31-90': 7,
    '91-365': 4,
    '366+': 1
}

# Countries considered higher risk
HIGH_RISK_COUNTRIES = {'Russia', 'China', 'North Korea', 'Iran'}


def map_age_to_score(age_days: int) -> float:
    """Map domain age in days to a score 1-10."""
    if age_days <= 30:
        return AGE_THRESHOLDS['0-30']
    elif age_days <= 90:
        return AGE_THRESHOLDS['31-90']
    elif age_days <= 365:
        return AGE_THRESHOLDS['91-365']
    else:
        return AGE_THRESHOLDS['366+']


def score_target(data: dict) -> float:
    """Compute a risk score (0-10) based on fetched data dict with keys:
       'whois': {'raw': str, 'creation_date': date},
       'geoip': {'country': str},
       'threat_feed': {'harmless': int, 'malicious': int, ...}
    """
    # Default component scores
    age_score = 5
    geo_score = 1
    threat_score = 0

    # 1) WHOIS age
    try:
        created = data.get('whois', {}).get('creation_date')
        if isinstance(created, (datetime.date, datetime.datetime)):
            delta = datetime.date.today() - (created if isinstance(created, datetime.date) else created.date())
            age_score = map_age_to_score(delta.days)
    except Exception:
        pass

    # 2) GeoIP risk
    try:
        country = data.get('geoip', {}).get('country')
        if country in HIGH_RISK_COUNTRIES:
            geo_score = 10
        else:
            geo_score = 1
    except Exception:
        pass

    # 3) Threat-feed ratio
    try:
        stats = data.get('threat_feed', {})
        total = sum(stats.values()) if isinstance(stats, dict) else 0
        malicious = stats.get('malicious', 0) if isinstance(stats, dict) else 0
        threat_score = (malicious / total * 10) if total > 0 else 0
    except Exception:
        pass

    # Weighted combination
    score = (
        WEIGHTS['age_days'] * age_score +
        WEIGHTS['geo_risk'] * geo_score +
        WEIGHTS['threat_hits'] * threat_score
    )
    # Clamp to 0-10 and round
    return round(max(0, min(score, 10)), 2)


if __name__ == '__main__':
    # Simple test harness
    from fetch import fetch_whois, geoip_lookup, fetch_threat_feed, IPV4_PATTERN
    import json

    targets = ['example.com', '8.8.8.8']
    for t in targets:
        print(f"\nScoring target: {t}")
        whois_data = fetch_whois(t)
        # Mock creation_date for example.com
        if 'creation_date' not in whois_data.get('raw', ''):
            whois_data['creation_date'] = datetime.date.today() - datetime.timedelta(days=400)
        geo_data = geoip_lookup(t) if IPV4_PATTERN.match(t) else {'country': None}
        feed_data = fetch_threat_feed(t).get('threat_feed', {})

        combined = {
            'whois': whois_data,
            'geoip': geo_data,
            'threat_feed': feed_data
        }
        score = score_target(combined)
        print('Combined data:', json.dumps(combined, default=str, indent=2))
        print('Score:', score)
