# [X] Image File Execution Options
# [X] Accounts
# [X] AppCert DLLs
# [X] AppInit DLLs
# [X] Bypass UAC
# [X] Authentication Packages
# [X] BITS 
# [ ] Change Default File Association
# [ ] File System Permissions Weakness
# [X] Hidden Files and Directories
# [X] Silent Process Exit
# [X] Logon Scripts
# [X] Services
# [X] Netsh Helper DLL
# [X] Environment Variables
# [X] Port Monitors
# [X] Registry Run Keys
# [X] Startup Folders
# [ ] HKLM\SOFTWARE\Microsoft\Cryptography\OID
# [ ] HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID
# [ ] HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust
# [ ] HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust
# [X] Scheduled Task
# [X] Screensaver
# [X] Security Support Provider
# [X] Shortcuts or symbolic links
# [X] Time Providers
# [X] Winlogon Helper DLL
# [X] TCP Connections
# [X] Clipboard
# [X] Volumes
# [X] Drivers
# [X] Partitions
# [X] Disks
# [X] Loaded modules by processes
# [X] Powershell history
# [X] Devices(ethernet, cd, wireless vs.)
# [ ] System32 hash check
# [X] AV, firewall condition
# [ ] Allowed denied ports
# [X] Office documents

function getRegistryValues() {
	"[+] REGISTRY VALUES" 
	
	# Creating HKU drive
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

	$users = @(Get-ChildItem -Path HKU:/ -Name)

	$paths = @(	
		"HKLM:\System\CurrentControlSet\Control\Session Manager",
		"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
		"HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
		"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
		"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
		"HKCU:\Environment\UserInitMprLogonScript",
		"HKLM:\SOFTWARE\Microsoft\Netsh",
		"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run ",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce ",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run ",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders ",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders ",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders ",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
		"HKCU:\Software\Microsoft\CurrentVersion\Run",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
		"HKU:\Software\Microsoft\Windows\CurrentVersion\Run",
		"HKCU:\Software\Microsoft\Windows\Run",
		"HKCU:\Software\Run",
		"HKCU:\Control Panel\Desktop",
		"HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders",
		"HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
		"HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
		"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls",
		"HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls",
		"HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls".
		"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
		"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
		"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
	)

	foreach($element in $paths) {
		"`t[-] " + $element
		if(($element | Select-String -Pattern "HKCU:\\") -ne "") {
			# Converting HKCU keys to HKU
			$j = $element.split(":")[1]
			foreach($i in $users) {
				$path = ("HKU:/" + $i + $j)
				"`t`t" + $path
				Get-ItemProperty -Path $path
			}
		} elseif(($element | Select-String -Pattern "TimeProviders") -ne "") {
			# Get all sub-TimeProviders
			$timeProviders = @(Get-ChildItem -Path $element -Name)
				foreach($k in $timeProviders) {
					$path = ($element + "\" + $k)
					"`t`t" + $path
					Get-ItemProperty -Path $path
				}
		} else {
			Get-ItemProperty -Path $element
		}
	}
}

function getStartupFolder() {
	"[+] STARTUP FOLDER"

	$users = Get-ChildItem -Path C:\Users

	foreach($i in $users) {
		Get-ChildItem -Path ("C:\Users\" + $i + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") -Recurse -ErrorAction SilentlyContinue -Force 
	}
}

function findOfficeDocs() {
	"[+] OFFICE DOCUMENTS"

	"[-] .docx"
	Get-ChildItem -Path C:\ -Filter *.docx -Recurse -ErrorAction SilentlyContinue -Force	

	"[-] .xlsx"
	Get-ChildItem -Path C:\ -Filter *.xlsx -Recurse -ErrorAction SilentlyContinue -Force	

	"[-] .pptx"
	Get-ChildItem -Path C:\ -Filter *.pptx -Recurse -ErrorAction SilentlyContinue -Force	
}

function findLNKFiles() {
	"[+] SHORTCUT FILES"

	$users = Get-ChildItem -Path C:\Users
	$shell = New-Object -ComObject Wscript.Shell

	foreach($i in $users) {
		Get-ChildItem -Path ("C:\Users\" + $i + "\Desktop") -Filter *.lnk -Recurse -ErrorAction SilentlyContinue -Force | foreach-object {
			"[-] " + "C:\Users\" + $i + "\Desktop"; $target = ("C:\Users\" + $i + "\Desktop\" + $_); ($target + "          -----          " + $shell.CreateShortcut($target).TargetPath) 
		}
	}
}

function getScheduledTasks() {
	"[+] SCHEDULED TASKS"

	Get-ScheduledTask
}

function getUsers() {
	"[+] USERS"

	"`t[-] Local Users"
	Get-LocalUser

	"`t[-] AD Users"
	Get-ADUser
}

function getServices() {
	"[+] SERVICES"

	Get-Service
}

function getHiddenFiles() {
	"[+] HIDDEN FILES"

	Get-ChildItem -Hidden -Recurse -Force
}

function getInstalledDrivers() {
	"[+] INSTALLED DRIVERS"

	Get-WindowsDriver –Online -All
}

function getDisks() {
	"[+] DISKS"

	Get-Disk
}

function getVolumes() {
	"[+] VOLUMES"

	Get-Volume
}

function getPartitions() {
	"[+] PARTITIONS"

	Get-Partition
}

function getClipboard() {
	"[+] CLIPBOARD"

	Get-Clipboard -Raw
}

function getTCPConnections() {
	"[+] TCP CONNECTIONS"

	Get-NetTCPConnection
}

function getBITS() {
	"[+] BITS"

	"[-] Bits Status"
	sc.exe query BITS

	"[-] Bits jobs"
	bitsadmin /list /allusers /verbose
}

function getProcessesNModules() {
	"[+] PROCESSES"

	$processes = Get-Process
	$processes
	
	"[+] MODULES"
	$processes | foreach-object { 
		$modules = $_ | Select Modules; 
		"`t[-] " + $_.ProcessName; 
		$modules.Modules 
	}
}

function getEnvironmentVariables() {
	"[+] ENVIRONMENTVARIABLES"

	Get-ChildItem Env:
}

function getHistory() {
	"[+] HISTORY"

	cat (PSReadlineOption).HistorySavePath
}

function getDrives() {
	"[+] DRIVES"

	Get-PSDrive
}

function getFirewallStatus() {
	"[+] FIREWALL STATUS"

	Get-NetFirewallProfile
}

function getAVStatus() {
	"[+] AV STATUS"

	Get-MpComputerStatus
}

function getDevices() {
	"[+] DEVICES"

	Get-Pnodevice
}

function getNetAdaptConf() {
	"[+] NETWORK ADAPTER CONFIG"

	Get-WmiObject Win32_NetworkAdapterConfiguration
}

function getComSystemInfo() {
	"[+] COMPUTER SYSTEM"

	Get-WmiObject Win32_ComputerSystem
}

function banner() {
    "             ___   ___  _   _             "
    "            / _ \ / _ \| | | |            "
    "       _ __| | | | | | | |_| |_ ___ _ __  "
    "      | '__| | | | | | | __| __/ _ \ '_ \ "
    "      | |  | |_| | |_| | |_| ||  __/ | | |"
    "      |_|   \___/ \___/ \__|\__\___|_| |_|"
    ""
    "            MalSearcher by Mert Degirmenci"
    '___________________________________________________'
}

function scriptManager() {
	banner
	getComSystemInfo
	getNetAdaptConf
	getDevices
	getAVStatus
	getDrives
	getFirewallStatus
	getEnvironmentVariables
	getHistory
	getProcessesNModules
	getBITS
	getTCPConnections
	getClipboard
	getPartitions
	getVolumes
	getDisks
	getInstalledDrivers
	getHiddenFiles
	getServices
	getUsers
	getScheduledTasks
	findLNKFiles
	findOfficeDocs
	getStartupFolder
	getRegistryValues
}

scriptManager
