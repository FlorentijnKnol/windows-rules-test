from python_rules import Rule

class RareScheduledTaskCreations(Rule):
    id = "b20f6158-9438-41be-83da-a5a16ac90c2b"
    title = "Rare Scheduled Task Creations"
    description = "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names."
    author = "Florian Roth"
    date = "2017/03/17"
    status = "experimental"
    tags = ['attack.persistence', 'attack.t1053', 'attack.s0111', 'attack.t1053.005']
    level = "low"

    def rule(self, e):
        count = self.stats.get('count', 'winlog.event_data.TaskName')
        if count is not None and count < 5:
            if e['winlog.event_id'] in [106]:
                return True
        return False

