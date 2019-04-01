# [X] .bash_profile .bashrc
# [X] Accounts
# [ ] Hidden Files
# [X] Kernel Modules
# [X] Scheduled Task
# [X] Setuid Setgid
# [ ] Trap
# [X] Sudo
# [X] Sudo Caching
# [X] History
# [X] Certificates
# [X] Environment Variables
# [X] Active Connections
# [X] tmp Folder
# [X] Processes
# [X] Services
# [ ] Devices
# [ ] Disks
# [ ] Partitions
# [X] Mount
# [X] fstab
# [X] Credentials in Files
# [X] SSH trusted keys
# [X] System Info
# [X] Network Info
# [X] Passwd & Shadow
# [X] ARP
# [X] Home folders
# [ ] World writable files
# [X] Apps installed
# [X] Login history
# [X] Groups
# [X] Rc.common
# [X] Launchctl
# [X] Startup Item

#!/usr/bin/python

import os

def executeCmd(cmd, level):
    if cmd is not "":
        stdout = os.popen(cmd[0], 'r')
        res = stdout.read().split('\n')
        printOut(res, level)
#        else:
#            for i in res:
#                innerOut = os.popen(cmd[1] + " " + i, 'r')
#                innerRes = stdout.read().split('\n')
#                printOut(innerRes, level)


def printOut(out, level):
    if out is not '':
        for i in out:
            print ((level * 4 * ' ') + '{:}').format(i)
        print
        print

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
    print ('{}').format("[+] SYSTEM INFO")
#    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/issue")
#    executeCmd({0:'cat /etc/issue'}, 3)
#    print ((2 * 4 * ' ') + '{:}').format("[-] /proc/version")
#    executeCmd({0:'cat /proc/version'}, 3)
    print ((2 * 4 * ' ') + '{:}').format("[-] hostname")
    executeCmd({0:'hostname'}, 3)
    print ((2 * 4 * ' ') + '{:}').format("[-] uname -a")
    executeCmd({0:'uname -a'}, 3)

    print ('{}').format("[+] NETWORK INFO")
    executeCmd({0:'ip a'}, 1)
    print
    executeCmd({0:'ifconfig -a'}, 1)
#    print
#    executeCmd({0:'route'}, 1)
    print
    executeCmd({0:'netstat -nr'}, 1)
    print
    executeCmd({0:'netstat -ap tcp'}, 1)
    print
    executeCmd({0:'lsof -PiTCP'}, 1)

    print ('{}').format("[+] MOUNT")
    executeCmd({0:'mount'}, 1)

    print ('{}').format("[+] FSTAB")
    executeCmd({0:'cat /etc/fstab'}, 1)

    print ('{}').format("[+] PASSWD")
    executeCmd({0:'cat /etc/passwd'}, 1)

    print ('{}').format("[+] GROUPS")
    executeCmd({0:'cat /etc/group'}, 1)
 
#    print ('{}').format("[+] SHADOW")
#    executeCmd({0:'cat /etc/shadow'}, 1)
 
    print ('{}').format("[+] BASH CONFIG FILES")
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/profile")
    executeCmd({0:'cat /etc/profile'}, 3)
    print
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/bashrc")
    executeCmd({0:'cat /etc/bashrc'}, 3)
    print
    stdout = os.popen("find /Users -name *bashrc  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    stdout = os.popen("find /Users -name *bash_profile  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    stdout = os.popen("find /Users -name *profile  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

#    print ('{}').format("[+] HIDDEN FILES")
#    executeCmd({0:"find / -name '.*' -exec ls -ld {} \; 2>/dev/null"}, 1)

    print ('{}').format("[+] LOGIN HISTORY")
    executeCmd({0:'w'}, 1)
    print
    executeCmd({0:"last"}, 1)

    print ('{}').format("[+] SUDOERS")
    executeCmd({0:"cat /etc/sudoers"}, 1)

    print ('{}').format("[+] SUDO CACHING")
#    executeCmd({0:"find /var/db/sudo -exec ls -ld {} \; 2>/dev/null"}, 1)
    stdout = os.popen("ls -d /var/db/sudo", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("ls -lA " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    print ('{}').format("[+] HOME FOLDERS")
    executeCmd({0:"ls -lA /Users"}, 1)

    print ('{}').format("[+] ENVIRONMENT VARIABLE")
    executeCmd({0:"env"}, 1)

    print ('{}').format("[+] TMP FOLDER")
    executeCmd({0:"ls -lA /tmp"}, 1)
    print
    executeCmd({0:'ls -lA /private/tmp'}, 1)

    print ('{}').format("[+] PROCESSES")
    executeCmd({0:"ps aux"}, 1)

#    print ('{}').format("[+] WORLD WRITABLE FOLDERS")
#    executeCmd({0:"find / \( -wholename '/Users/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root"}, 1)
#
#    print ('{}').format("[+] WORLD WRITABLE FILES")
#    executeCmd({0:"find / \( -wholename '/Users/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root"}, 1)

    print ('{}').format("[+] SUID & SGID")
    executeCmd({0:"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null"}, 1)

    print ('{}').format("[+] HISTORY FILES")
    stdout = os.popen("find /Users -name *history  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    print ('{}').format("[+] SSH TRUSTED KEYS")
    stdout = os.popen("find /Users -name authorized_keys 2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    print ('{}').format("[+] CERTIFICATES")
    executeCmd({0:"security find-certificate -a"}, 1)

    print ('{}').format("[+] SCHEDULED JOBS")
    print ((2 * 4 * ' ') + '{:}').format("[-] /System/Library/LaunchDaemons")
    stdout = os.popen("ls /System/Library/LaunchDaemons/", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            path = "/System/Library/LaunchDaemons" + i
            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
            stdout = os.popen("cat " + path, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 
    print ((2 * 4 * ' ') + '{:}').format("[-] /Library/LaunchDaemons/")
    stdout = os.popen("ls /Library/LaunchDaemons/", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            path = "/Library/LaunchDaemons/" + i
            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
            stdout = os.popen("cat " + path, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 
    print ((2 * 4 * ' ') + '{:}').format("[-] /Library/LaunchAgents/")
    stdout = os.popen("ls /Library/LaunchAgents/", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            path = "/Library/LaunchDaemons/" + i
            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
            stdout = os.popen("cat " + path, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 
    print ((2 * 4 * ' ') + '{:}').format("[-] LaunchAgents Under /Users")
    stdout = os.popen("find /users/ -name launchagents -type d 2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            stdout = os.popen("ls " + i, 'r')
            res = stdout.read().split('\n')
            for j in res:
                if j != "":
                    path = i + "/" + j
                    print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
                    stdout = os.popen("cat " + path, 'r')
                    res = stdout.read().split('\n')
                    printOut(res, 3)
                    print 

#    print ('{}').format("[+] LOGIN ITEM")
#    stdout = os.popen("ls /Users", 'r')
#    res = stdout.read().split('\n')
#    for i in res:
#        if i != "":
#            path = "/Users/" + i + "/Library/Preferences/"
#            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
#            stdout = os.popen("ls " + path, 'r')
#            res = stdout.read().split('\n')
#            for j in res:
#                if j != "":
#                    pathCat = path + j
#                    print ((2 * 4 * ' ') + '{:}').format("[-] " + pathCat)
#                    stdout = os.popen("cat " + pathCat, 'r')
#                    res = stdout.read().split('\n')
#                    print res
#                    printOut(res, 3)
#                    print 

    print ('{}').format("[+] LAUNCHCTL")
    executeCmd({0:"launchctl list"}, 1)

    print ('{}').format("[+] STARTUP ITEM")
    stdout = os.popen("ls /Library/StartupItems", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            path = "/Library/StartupItems" + i
            print ((2 * 4 * ' ') + '{:}').format("[-] " + path)
            stdout = os.popen("cat " + path, 'r')
            res = stdout.read().split('\n')
            printOut(res, 2)
            print 

    print ('{}').format("[+] RC.COMMON")
    executeCmd({0:"cat /etc/rc.common"}, 1)

    print ('{}').format("[+] FIREWALL")
    executeCmd({0:"pfctl -s all"}, 1)

    print ('{}').format("[+] APPS INSTALLED")
    executeCmd({0:"ls -la /Applications/"}, 1)

    print ('{}').format("[+] SERVICES")
    executeCmd({0:"launchctl list"}, 1)
    print
    executeCmd({0:"ls -lA /Library/StartupItems"}, 1)

    print ('{}').format("[+] KERNEL MODULES")
    executeCmd({0:"kextstat"}, 1)

    print ('{}').format("[+] ARP")
    executeCmd({0:"arp -a"}, 1)

    # https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
    print ('{}').format("[+] CREDENTIALS IN FILES")
    print ((2 * 4 * ' ') + '{:}').format("[-] Config Files @ /etc")
    executeCmd({0:"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null"}, 3)
    print ((2 * 4 * ' ') + '{:}').format("[-] Files @ /Users")
    executeCmd({0:"find /Users  2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null"}, 3)

if __name__ == "__main__":
    main()
