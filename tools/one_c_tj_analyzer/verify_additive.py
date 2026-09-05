"""Independent saved-event accumulators; O(groups) state plus one numeric event.

Group populations (no CALL/candidate/source-location joins):
dataset: (dataset_id,event_type), every event including unknown timestamps.
sql: (measurement_id,fingerprint), DB with SQL, linked or unlinked, all datasets.
lock: (measurement_id,event_type,canonical context), checked auxiliary lock events.
"""
from numeric_quality import CounterStats, FIELDS


POPULATIONS = {
    'dataset': (2, "SELECT e.dataset_id AS g0,e.event_type AS g1,e.event_id,e.duration_us,0 AS linked FROM events e"),
    'sql': (2, "SELECT e.measurement_id AS g0,p.sql_fingerprint_sha256 AS g1,e.event_id,e.duration_us,0 AS linked "
            "FROM events e JOIN db_events d USING(event_id) JOIN sql_normalizations n USING(sql_text_id) JOIN sql_patterns p USING(pattern_id)"),
    'lock': (3, "SELECT e.measurement_id AS g0,e.event_type AS g1,a.context AS g2,e.event_id,e.duration_us,"
             "a.parent_event_id IS NOT NULL AS linked FROM events e JOIN checked_aux a USING(event_id) WHERE a.category='lock'"),
}


class AdditiveStats:
    def __init__(self):
        self.count = self.total = self.maximum = self.middle = self.linked = 0
        self.over = [0] * 4
        self.quality = {name: CounterStats() for name in FIELDS}

    def add_event(self, duration, linked):
        self.count += 1
        self.total += duration
        self.maximum = max(self.maximum, duration)
        self.linked += linked
        self.middle += 500_000 <= duration <= 2_000_000
        for i, seconds in enumerate((1, 5, 10, 30)):
            self.over[i] += duration >= seconds * 1_000_000

    def as_dict(self):
        return {'count': self.count, 'duration_us': self.total,
                'avg_us': round(self.total/self.count, 3) if self.count else 0.0,
                'max_us': self.maximum, 'count_0_5_to_2s': self.middle,
                **{f'over_{s}s': self.over[i] for i, s in enumerate((1, 5, 10, 30))},
                'numeric_quality': {name: stats.as_dict() for name, stats in self.quality.items()}}


def additive_groups(connection, family, require):
    """Two ordered reads per family, never a list/cache of its event population.

Only integer additions precede final division/rounding. Each event's numeric
fields are consumed separately, with exact coverage and uniqueness checks.
"""
    width, population = POPULATIONS[family]
    events = connection.execute('SELECT * FROM (' + population + ') ORDER BY event_id')
    numeric = connection.execute(
        'SELECT ' + ','.join(f'p.g{i}' for i in range(width)) + ',p.event_id,n.field_name,n.state,n.value_int '
        'FROM (' + population + ') p JOIN numeric_values n ON n.event_id=p.event_id '
        'ORDER BY p.event_id,n.field_name')
    groups, previous = {}, None
    try:
        value = next(numeric, None)
        for event in events:
            key = tuple(event[f'g{i}'] for i in range(width))
            event_key = (*key, event['event_id'])
            require(event['event_id'] != previous, 'aggregate population duplicates events')
            previous = event['event_id']
            if key not in groups:
                groups[key] = AdditiveStats()
            target = groups[key]
            target.add_event(event['duration_us'], event['linked'])
            fields = set()
            while value is not None and tuple(value[:width+1]) == event_key:
                name = value['field_name']
                require(name in FIELDS and name not in fields, 'missing/extra/duplicate numeric fields')
                fields.add(name)
                target.quality[name].add({'state': value['state'], 'value': value['value_int']})
                value = next(numeric, None)
            require(fields == set(FIELDS), 'counter coverage differs from event population')
        require(value is None, 'numeric stream outside event population')
    finally:
        events.close()
        numeric.close()
    return groups
