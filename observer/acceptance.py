"""First-cycle acceptance is stricter than ordinary outage monitoring."""
def accepted(report):
    return (report.get('schema') == 1 and report.get('clock_trusted') is True
            and report.get('provider_heartbeat') is True
            and report.get('spool_events') == 0 and report.get('spool_dropped') == 0
            and report.get('outcomes', {}).get('wan_edge') is True
            and report.get('outcomes', {}).get('edge_exposure') is True
            and report.get('outcomes', {}).get('private_queue') in (None, True)
            and report.get('incidents') and not any(report['incidents'].values()))
