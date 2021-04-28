from python_rules import Rule, deep_get


class SuspiciousMultipleFileRenameOrDeleteOccurred(Rule):
    id = "97919310-06a7-482c-9639-92b67ed63cf8"
    title = "Suspicious Multiple File Rename Or Delete Occurred"
    description = "Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity)."
    author = "Vasiliy Burov, oscd.community"
    date = "2020/10/16"
    status = "experimental"
    tags = ['attack.impact', 'attack.t1486']
    references = ['https://www.manageengine.com/data-security/how-to/how-to-detect-ransomware-attacks.html']
    level = "medium"

    def rule(self, e):
        count = self.stats.get('count', 'winlog.event_data.')
        if count is not None and count > 10:
            if deep_get(e, 'winlog', 'event_data', 'AccessList') in ['%%1537']:
                if deep_get(e, 'winlog', 'event_id') in [4663]:
                    if deep_get(e, 'winlog', 'event_data', 'Keywords') in ['0x8020000000000000']:
                        if deep_get(e, 'winlog', 'event_data', 'ObjectType') in ['File']:
                            return True
        return False

