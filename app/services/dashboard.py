from datetime import datetime, timedelta, timezone

from app.services import search


def overview(database, hours):
    end = datetime.now(timezone.utc)
    since = end - timedelta(hours=hours)
    stats = search.statistics(database, search.event_filter(start=since, end=end), 'hour')
    return {
        'since': since,
        'hours': hours,
        'open_alerts': database.siem_alerts.count_documents({'status': {'$in': ['open', 'acknowledged']}}),
        'active_incidents': database.siem_incidents.count_documents({'status': {'$ne': 'closed'}}),
        'enabled_rules': database.siem_rules.count_documents({'enabled': True}),
        'hourly_events': stats.pop('series'),
        **stats,
    }
