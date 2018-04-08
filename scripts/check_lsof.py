#!/usr/bin/python

# Import System Required Paths
import sys
sys.path.append('/usr/local/src/volatility-master')

# Import Volalatility
import volatility.conf as conf
import volatility.registry as registry
registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
import volatility.addrspace as addrspace
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE="LinuxDebian31604x64"
config.LOCATION = "vmi://debian-hvm"

# Other imports
import time

# Retrieve lsof plugin
import volatility.plugins.linux.lsof as lsofPlugin
import volatility.plugins.linux.pslist as linux_pslist
lsofData = lsofPlugin.linux_lsof(config)

lsof_plugin_start_time = time.time()

tasks = linux_pslist.linux_pslist(config).allprocs()

for task in tasks:
	if str(task.comm) == 'test':
		mytasks = [task]
		for msg in lsofData.generator(mytasks):
			print msg
print("--- List Open Files Time Taken: %s seconds ---" % (time.time() - lsof_plugin_start_time))
