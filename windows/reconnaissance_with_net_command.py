from python_rules import Rule, deep_get

RECON_ACTIVITY = {'tasklist',
                  'net time',
                  'systeminfo',
                  'whoami',
                  'nbtstat',
                  'net start',
                  '*\\net1 start',
                  'qprocess',
                  'nslookup',
                  'hostname.exe',
                  '*\\net1 user /domain',
                  '*\\net1 group /domain',
                  '*\\net1 group "domain admins" /domain',
                  '*\\net1 group "Exchange Trusted Subsystem" /domain',
                  '*\\net1 accounts /domain',
                  '*\\net1 user net localgroup administrators',
                  'netstat -an'
                  }


class ReconnaissanceActivitywithNetCommand(Rule):
    id = "2887e914-ce96-435f-8105-593937e90757"
    title = "Reconnaissance Activity with Net Command"
    description = "Detects a set of commands often used in recon stages by different attack groups"
    author = "Florian Roth, Markus Neis"
    date = "2018/08/22"
    status = "experimental"
    tags = ['attack.discovery', 'attack.t1087', 'attack.t1082', 'car.2016-03-001']
    references = ['https://twitter.com/haroonmeer/status/939099379834658817', 'https://twitter.com/c_APT_ure/status/939475433711722497', 'https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html']
    level = "medium"

    def rule(self, e):
        filter_fn = lambda e: deep_get(e, 'winlog', 'event_data', 'CommandLine') in RECON_ACTIVITY
        count = self.stats.filter(filter_id="recon_filter", filter_function=filter_fn).windowed("1H").get('total_count')
        if count is not None and count > 4:
            if deep_get(e, 'winlog', 'event_data', 'CommandLine') in RECON_ACTIVITY:
                return True
        return False