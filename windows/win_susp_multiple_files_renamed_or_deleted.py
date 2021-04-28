from python_rules import Rule, nest_get


class SuspiciousMultipleFileRenameOrDeleteOccurred(Rule):
    id = "97919310-06a7-482c-9639-92b67ed63cf8"
    title = "Suspicious Multiple File Rename Or Delete Occurred"
    description = "Detects multiple file rename or delete events occurrence within a specified period of time by a " \
                  "same user (these events may signalize about ransomware activity). "
    author = "Vasiliy Burov, oscd.community"
    date = "2020/10/16"
    status = "experimental"
    tags = ['attack.impact', 'attack.t1486']
    references = ['https://www.manageengine.com/data-security/how-to/how-to-detect-ransomware-attacks.html']
    level = "medium"

    def rule(self, e):

        def filter_fn(ev):
            try:
                return nest_get(ev, 'winlog.event_data.AccessList') in ['%%1537'] and \
                       nest_get(ev, 'winlog.event_id') in [4663] and \
                       nest_get(ev, 'winlog.event_data.Keywords') in ['0x8020000000000000'] and \
                       nest_get(ev, 'winlog.event_data.ObjectType') in ['File']
            except KeyError:
                return False

        count = self.stats.filter(filter_id="supsmultidelete",
                                  filter_function=filter_fn).windowed("1m").get('count',
                                                                                 'winlog.event_data.SubjectLogonId')
        if count is not None and count > 10 and filter_fn(e):
            return False

