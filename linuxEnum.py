# [X] .bash_profile .bashrc
# [X] Accounts
# [X] Hidden Files
# [ ] Kernel Modules
# [X] Scheduled Task
# [X] Setuid Setgid
# [ ] Trap
# [X] Sudo
# [X] Sudo Caching
# [X] History
# [ ] Certificates
# [ ] Clipboard
# [X] Environment Variables
# [X] Active Connections
# [X] tmp Folder
# [X] Processes
# [ ] Firewall status
# [ ] Services
# [ ] Devices
# [ ] Disks
# [ ] Partitions
# [X] Mount
# [X] fstab
# [ ] Credentials in Files
# [X] SSH trusted keys
# [X] System Info
# [X] Network Info
# [X] Passwd & Shadow
# [ ] ARP
# [X] Home folders
# [X] World writable files
# [ ] Apps installed
# [X] Login history
# [X] Groups

#!/usr/bin/python

import os

def executeCmd(cmd):
    if cmd is not "":
        stdout = os.popen(cmd, 'r')
        res = stdout.read().split('\n')
        printOut(res, 1)

def printOut(out, level):
    if out is not '':
        for i in out:
            print ((level * 4 * ' ') + '{:}').format(i)


def banner():
    print
    print "             ___   ___  _   _             "
    print "            / _ \ / _ \| | | |            "
    print "       _ __| | | | | | | |_| |_ ___ _ __  "
    print "      | '__| | | | | | | __| __/ _ \ '_ \ "
    print "      | |  | |_| | |_| | |_| ||  __/ | | |"
    print "      |_|   \___/ \___/ \__|\__\___|_| |_|"
    print
    print "{:^}".format('malSearcher by Mert Degirmenci')
    print '___________________________________________________'
    print

def main():
    banner()
    print 
    print 
    print ('{}').format("[+] SYSTEM INFO")
    executeCmd('cat /etc/issue')
    print
    executeCmd('cat /proc/version')
    print
    executeCmd('hostname')
    print
    executeCmd('uname -a')

    print 
    print 
    print ('{}').format("[+] NETWORK INFO")
    executeCmd('ip a')
    print
    executeCmd('ifconfig -a')
    print
    executeCmd('route')
    print
    executeCmd('netstat -antup')

    print 
    print 
    print ('{}').format("[+] MOUNT")
    executeCmd('mount')


    print 
    print 
    print ('{}').format("[+] FSTAB")
    executeCmd('cat /etc/fstab')

    print 
    print 
    print ('{}').format("[+] PASSWD")
    executeCmd('cat /etc/passwd')

    print 
    print 
    print ('{}').format("[+] GROUPS")
    executeCmd('cat /etc/group')
 
    print 
    print 
    print ('{}').format("[+] SHADOW")
    executeCmd('cat /etc/shadow')
 
    print 
    print 
    print ('{}').format("[+] BASH CONFIG FILES")
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/profile")
    executeCmd('cat /etc/profile')
    print
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/bash.bashrc")
    executeCmd('cat /etc/bash.bashrc')
    print
    stdout = os.popen("find /home -name *bashrc  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
        stdout = os.popen("cat " + i, 'r')
        res = stdout.read().split('\n')
        printOut(res, 2)
        print 
    stdout = os.popen("find /home -name *bash_profile  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
        stdout = os.popen("cat " + i, 'r')
        res = stdout.read().split('\n')
        printOut(res, 2)
        print 

    print 
    print 
    print ('{}').format("[+] HIDDEN FILES")
    executeCmd("find / -name '.*' -exec ls -ld {} \; 2>/dev/null")

    print 
    print 
    print ('{}').format("[+] LOGIN HISTORY")
    executeCmd('w')
    print
    executeCmd('last')

    print 
    print 
    print ('{}').format("[+] SUDOERS")
    executeCmd('cat /etc/sudoers')

    print 
    print 
    print ('{}').format("[+] SUDO CACHING")
    executeCmd("find /var/db/sudo -exec ls -ld {} \; 2>/dev/null")

    print 
    print 
    print ('{}').format("[+] HOME FOLDERS")
    executeCmd('ls -lA /home')

    print 
    print 
    print ('{}').format("[+] ENVIRONMENT VARIABLE")
    executeCmd('env')

    print 
    print 
    print ('{}').format("[+] TMP FOLDER")
    executeCmd('ls -lA /tmp')

    print 
    print 
    print ('{}').format("[+] PROCESSES")
    executeCmd('ps aux')

    print 
    print 
    print ('{}').format("[+] WORLD WRITABLE FOLDERS")
    executeCmd("find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root")

    print 
    print 
    print ('{}').format("[+] WORLD WRITABLE FILES")
    executeCmd("find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root")

    print 
    print 
    print ('{}').format("[+] SUID & SGID")
    executeCmd("find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null")

    print 
    print 
    print ('{}').format("[+] HISTORY FILES")
    stdout = os.popen("find /home -name *history  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
        stdout = os.popen("cat " + i, 'r')
        res = stdout.read().split('\n')
        printOut(res, 2)
        print 

    print 
    print 
    print ('{}').format("[+] SSH TRUSTED KEYS")
    stdout = os.popen("find /home -name authorized_keys 2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
        stdout = os.popen("cat " + i, 'r')
        res = stdout.read().split('\n')
        printOut(res, 2)
        print 

    print 
    print 
    print ('{}').format("[+] SCHEDULED JOBS")
    stdout = os.popen("find /etc -name cron* 2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        stdout = os.popen("ls " + i, 'r')
        res = stdout.read().split('\n')
        
        for j in res:
            path = i + "/" + j
            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
            stdout = os.popen("cat " + path, 'r')
            res = stdout.read().split('\n')
            printOut(res, 2)
            print 

if __name__ == "__main__":
    main()
