from python_rules import Rule, deep_get


class ExecutionviaCLMutexverifiersps12Lines(Rule):
    id = "6609c444-9670-4eab-9636-fe4755a851ce"
    title = "Execution via CL_Mutexverifiers.ps1 (2 Lines)"
    description = "Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module"
    author = "oscd.community, Natalia Shornikova"
    date = "2020/10/14"
    status = "experimental"
    tags = ['attack.defense_evasion', 'attack.t1216']
    references = ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/CL_mutexverifiers.yml', 'https://twitter.com/pabraeken/status/995111125447577600']
    level = "high"

    def rule(self, e):
        count = self.stats.groupby('Computer').get('count', 'winlog.event_data.ScriptBlockText')
        if count is not None and count > 2:
            if deep_get(e, 'winlog', 'event_id') in [4104]:
                if list(filter(lambda x: x in deep_get(e, 'winlog', 'event_data', 'ScriptBlockText'), ['CL_Mutexverifiers.ps1', 'runAfterCancelProcess'])):
                    return True
        return False

