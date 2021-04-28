from python_rules import Rule

class QuickExecutionofaSeriesofSuspiciousCommands(Rule):
    id = "61ab5496-748e-4818-a92f-de78e20fe7f1"
    title = "Quick Execution of a Series of Suspicious Commands"
    description = "Detects multiple suspicious process in a limited timeframe"
    author = "juju4"
    date = "2019/01/16"
    status = "experimental"
    tags = ['car.2013-04-002']
    references = ['https://car.mitre.org/wiki/CAR-2013-04-002']
    level = "low"

    def rule(self, e):
        count = self.stats.get('count', 'winlog.event_data.MachineName')
        if count is not None and count > 5:
            if e['winlog.event_data.CommandLine'] in ['arp.exe', 'at.exe', 'attrib.exe', 'cscript.exe', 'dsquery.exe', 'hostname.exe', 'ipconfig.exe', 'mimikatz.exe', 'nbtstat.exe', 'net.exe', 'netsh.exe', 'nslookup.exe', 'ping.exe', 'quser.exe', 'qwinsta.exe', 'reg.exe', 'runas.exe', 'sc.exe', 'schtasks.exe', 'ssh.exe', 'systeminfo.exe', 'taskkill.exe', 'telnet.exe', 'tracert.exe', 'wscript.exe', 'xcopy.exe', 'pscp.exe', 'copy.exe', 'robocopy.exe', 'certutil.exe', 'vssadmin.exe', 'powershell.exe', 'wevtutil.exe', 'psexec.exe', 'bcedit.exe', 'wbadmin.exe', 'icacls.exe', 'diskpart.exe']:
                return True
        return False