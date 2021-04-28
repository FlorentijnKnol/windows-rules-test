from python_rules import Rule, deep_get


class EnumerationviatheGlobalCatalog(Rule):
    id = "619b020f-0fd7-4f23-87db-3f51ef837a34"
    title = "Enumeration via the Global Catalog"
    description = "Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Threshold according to domain width."
    author = "Chakib Gzenayi (@Chak092), Hosni Mribah"
    date = "2020/05/11"
    tags = ['attack.discovery', 'attack.t1087', 'attack.t1087.002']
    level = "medium"

    def rule(self, e):
        count = self.stats.windowed("1H").get('count', 'source.ip')
        if count is not None and count > 2000:
            if deep_get(e, 'winlog', 'event_data', 'DestinationPort') in [3268, 3269]:
                if deep_get(e, 'winlog', 'event_id') in [5156]:
                    return True
        return False

