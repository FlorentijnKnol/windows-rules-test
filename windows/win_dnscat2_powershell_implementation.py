from python_rules import Rule, deep_get


class DNSCat2PowershellImplementationDetectionViaProcessCreation(Rule):
    id = "b11d75d6-d7c1-11ea-87d0-0242ac130003"
    title = "DNSCat2 Powershell Implementation Detection Via Process Creation"
    description = "The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally."
    author = "Cian Heasley"
    date = "2020/08/08"
    status = "experimental"
    tags = ['attack.command_and_control', 'attack.t1071', 'attack.t1071.004', 'attack.t1001.003', 'attack.t1041']
    references = ['https://github.com/lukebaggett/dnscat2-powershell', 'https://blu3-team.blogspot.com/2019/08/powershell-dns-c2-notes.html', 'https://ragged-lab.blogspot.com/2020/06/it-is-always-dns-powershell-edition.html']
    level = "high"

    def rule(self, e):
        def filter_fn(ev):
            commline = deep_get(ev, 'winlog', 'event_data', 'CommandLine', default="")
            image = deep_get(ev, 'winlog', 'event_data', 'Image', default="")
            parent_image = deep_get(ev, 'winlog', 'event_data', 'Image', default="")
            return (commline.endswith('\\nslookup.exe') or image.endswith('\\nslookup.exe') and
                parent_image.endswith('\\powershell.exe'))

        count = self.stats.filter(filter_id="nslookup_psl", filter_function=filter_fn).windowed("1d").get("total_count")
        return count > 100 and filter_fn(e)

