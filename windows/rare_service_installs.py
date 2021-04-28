from python_rules import Rule, deep_get


class RareServiceInstalls(Rule):
    id = "66bfef30-22a5-4fcd-ad44-8d81e60922ae"
    title = "Rare Service Installs"
    description = "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services"
    author = "Florian Roth"
    date = "2017/03/08"
    status = "experimental"
    tags = ['attack.persistence', 'attack.privilege_escalation', 'attack.t1050', 'car.2013-09-005', 'attack.t1543.003']
    level = "low"

    relation_fields = ["winlog.event_data.ServiceFileName"]

    def rule(self, e):
        count = self.stats.windowed("7d").get('count', 'winlog.event_data.ImagePath')
        if count is not None and count < 5 and not \
                deep_get(e, "winlog", "event_data", "ImagePath", default="").endswith("MpKslDrv.sys"):
            if deep_get(e, 'winlog', 'event_id') in [7045]:
                return True
        return False