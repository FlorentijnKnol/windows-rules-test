from python_rules import Rule, nest_get

SUSP_COMMANDS = {'arp.exe',
                 'at.exe',
                 'attrib.exe',
                 'cscript.exe',
                 'dsquery.exe',
                 'hostname.exe',
                 'ipconfig.exe',
                 'mimikatz.exe',
                 'nbtstat.exe',
                 'net.exe',
                 'netsh.exe',
                 'nslookup.exe',
                 'ping.exe',
                 'quser.exe',
                 'qwinsta.exe',
                 'reg.exe',
                 'runas.exe',
                 'sc.exe',
                 'schtasks.exe',
                 'ssh.exe',
                 'systeminfo.exe',
                 'taskkill.exe',
                 'telnet.exe',
                 'tracert.exe',
                 'wscript.exe',
                 'xcopy.exe',
                 'pscp.exe',
                 'copy.exe',
                 'robocopy.exe',
                 'certutil.exe',
                 'vssadmin.exe',
                 'powershell.exe',
                 'wevtutil.exe',
                 'psexec.exe',
                 'bcedit.exe',
                 'wbadmin.exe',
                 'icacls.exe',
                 'diskpart.exe'
}

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
        filter_fn = lambda ev: nest_get(ev, 'winlog.event_data.Commandline') in SUSP_COMMANDS
        count = self.stats.filter(filter_id="quickexsusp", filter_function=filter_fn).windowed("30m").get("total_count")
        return count is not None and count > 5 and filter_fn(e)