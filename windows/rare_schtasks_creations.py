from python_rules import Rule

class RareSchtasksCreations(Rule):
    id = "b0d77106-7bb0-41fe-bd94-d1752164d066"
    title = "Rare Schtasks Creations"
    description = "Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code"
    author = "Florian Roth"
    date = "2017/03/23"
    status = "experimental"
    tags = ['attack.execution', 'attack.privilege_escalation', 'attack.persistence', 'attack.t1053', 'car.2013-08-001', 'attack.t1053.005']
    level = "low"

    def rule(self, e):
        count = self.stats.get('count', 'winlog.event_data.TaskName')
        if count is not None and count < 5:
            if e['winlog.event_id'] in [4698]:
                return True
        return False
