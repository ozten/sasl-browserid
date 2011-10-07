#!/usr/bin/env python
"""
Privileged Unit Test Suite.

These tests should be run inside of a Vagrant VM.

They exercise the low level functions of the C plugin.

A minimal set of programs has been written which expose
units of code to the system as CLI. They are scripted below
via Python's sys.exec to provide a convient way to test
corner cases, etc.
"""
import re
import subprocess
import unittest


class InstalledProperlyTestCase(unittest.TestCase):
    def test_pluginviewer_sees_browserid(self):
        try:
            p = subprocess.Popen(['saslpluginviewer'], stdout=subprocess.PIPE)
        except OSError:
            p = subprocess.Popen(['pluginviewer'], stdout=subprocess.PIPE)
        p.wait()
        output = p.stdout.readlines()
        seen = self._parse_pv(output)
        self.assertTrue(seen['client'], 'Test run under sudo, right?')
        self.assertTrue(seen['server'])

    def _parse_pv(self, output):
        """Examines pluginviewer output and looks for BROWSER-ID"""
        in_client = False
        in_server = False
        seen = dict(client=False, server=False)
        for l in output:
            line = l.rstrip()
            if "Installed SASL (server side) mechanisms are:" == line:
                in_client = False
                in_server = True
            elif "Installed SASL (client side) mechanisms are:" == line:
                in_client = True
                in_server = False
            elif re.match('Installed.*mechanisms are:$', line):
                in_client = False
                in_server = False
            elif re.match('.*SASL mechanism: BROWSER-ID, .*', line):
                if in_client:
                    seen['client'] = True
                elif in_server:
                    seen['server'] = True
                else:
                    self.fail("Got an unexpected BROWSER-ID plugin [%s]" % line)
            else:
                pass
        return seen

if __name__ == '__main__':
    unittest.main()

