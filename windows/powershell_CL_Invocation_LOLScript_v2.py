from python_rules import Rule, deep_get


class ExecutionviaCLInvocationps12Lines(Rule):
    id = "f588e69b-0750-46bb-8f87-0e9320d57536"
    title = "Execution via CL_Invocation.ps1 (2 Lines)"
    description = "Detects Execution via SyncInvoke in CL_Invocation.ps1 module"
    author = "oscd.community, Natalia Shornikova"
    date = "2020/10/14"
    status = "experimental"
    tags = ['attack.defense_evasion', 'attack.t1216']
    references = ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/Cl_invocation.yml', 'https://twitter.com/bohops/status/948061991012327424']
    level = "high"

    def rule(self, e):
        count = self.stats.groupby('winlog.computer_name').get('count', 'winlog.event_data.ScriptBlockText')
        if count is not None and count > 2:
            if deep_get(e, 'winlog', 'event_id')in [4104]:
                if list(filter(lambda x: x in deep_get(e, 'winlog', 'event_data', 'ScriptBlockText'),
                               ['CL_Invocation.ps1', 'SyncInvoke'])):
                    return True
        return False

