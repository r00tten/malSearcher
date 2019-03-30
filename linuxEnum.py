# [X] .bash_profile .bashrc
# [X] Accounts
# [X] Hidden Files
# [X] Kernel Modules
# [X] Scheduled Task
# [X] Setuid Setgid
# [X] Trap
# [X] Sudo
# [X] Sudo Caching
# [X] History
# [X] Certificates
# [ ] Clipboard
# [X] Environment Variables
# [X] Active Connections
# [X] tmp Folder
# [X] Processes
# [X] Firewall status
# [X] Services
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
# [X] ARP
# [X] Home folders
# [X] World writable files
# [X] Apps installed
# [X] Login history
# [X] Groups

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
    executeCmd({0:'cat /etc/issue'}, 1)
    print
    executeCmd({0:'cat /proc/version'}, 1)
    print
    executeCmd({0:'hostname'}, 1)
    print
    executeCmd({0:'uname -a'}, 1)

    print ('{}').format("[+] NETWORK INFO")
    executeCmd({0:'ip a'}, 1)
    print
    executeCmd({0:'ifconfig -a'}, 1)
    print
    executeCmd({0:'route'}, 1)
    print
    executeCmd({0:'netstat -antup'}, 1)

    print ('{}').format("[+] MOUNT")
    executeCmd({0:'mount'}, 1)

    print ('{}').format("[+] FSTAB")
    executeCmd({0:'cat /etc/fstab'}, 1)

    print ('{}').format("[+] PASSWD")
    executeCmd({0:'cat /etc/passwd'}, 1)

    print ('{}').format("[+] GROUPS")
    executeCmd({0:'cat /etc/group'}, 1)
 
    print ('{}').format("[+] SHADOW")
    executeCmd({0:'cat /etc/shadow'}, 1)
 
    print ('{}').format("[+] BASH CONFIG FILES")
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/profile")
    executeCmd({0:'cat /etc/profile'}, 3)
    print
    print ((2 * 4 * ' ') + '{:}').format("[-] /etc/bash.bashrc")
    executeCmd({0:'cat /etc/bash.bashrc'}, 3)
    print
    stdout = os.popen("find /home -name *bashrc  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    stdout = os.popen("find /home -name *bash_profile  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    stdout = os.popen("find /home -name *profile  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    print ('{}').format("[+] HIDDEN FILES")
    executeCmd({0:"find / -name '.*' -exec ls -ld {} \; 2>/dev/null"}, 1)

    print ('{}').format("[+] LOGIN HISTORY")
    executeCmd({0:'w'}, 1)
    print
    executeCmd({0:"last"}, 1)

    print ('{}').format("[+] SUDOERS")
    executeCmd({0:"cat /etc/sudoers"}, 1)

    print ('{}').format("[+] SUDO CACHING")
    executeCmd({0:"find /var/db/sudo -exec ls -ld {} \; 2>/dev/null"}, 1)

    print ('{}').format("[+] HOME FOLDERS")
    executeCmd({0:"ls -lA /home"}, 1)

    print ('{}').format("[+] ENVIRONMENT VARIABLE")
    executeCmd({0:"env"}, 1)

    print ('{}').format("[+] TMP FOLDER")
    executeCmd({0:"ls -lA /tmp"}, 1)

    print ('{}').format("[+] PROCESSES")
    executeCmd({0:"ps aux"}, 1)

    print ('{}').format("[+] WORLD WRITABLE FOLDERS")
    executeCmd({0:"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root"}, 1)

    print ('{}').format("[+] WORLD WRITABLE FILES")
    executeCmd({0:"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root"}, 1)

    print ('{}').format("[+] SUID & SGID")
    executeCmd({0:"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null"}, 1)

    print ('{}').format("[+] HISTORY FILES")
    stdout = os.popen("find /home -name *history  2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    print ('{}').format("[+] SSH TRUSTED KEYS")
    stdout = os.popen("find /home -name authorized_keys 2>/dev/null", 'r')
    res = stdout.read().split('\n')
    for i in res:
        if i != "":
            print ((2 * 4 * ' ') + '{:}').format("[-] " + i)
            stdout = os.popen("cat " + i, 'r')
            res = stdout.read().split('\n')
            printOut(res, 3)
            print 

    # https://unix.stackexchange.com/questions/97244/list-all-available-ssl-ca-certificates
    print ('{}').format("[+] CERTIFICATES")
    executeCmd({0:"awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt"}, 1)

    print ('{}').format("[+] SCHEDULED JOBS")
    stdout = os.popen("find /etc -name cron* 2>/dev/null", 'r')
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
                    printOut(res, 2)
                    print 

    print ('{}').format("[+] FIREWALL")
    print ((2 * 4 * ' ') + '{:}').format("[-] Firewall Status")
    executeCmd({0:"systemctl status iptables"}, 2)
    print
    iptables = {0:'filter', 1:'nat', 2:'mangle', 3:'raw', 4:'security'}
    for i in range(len(iptables)):
        print ((2 * 4 * ' ') + '{:}').format("[-] " + str(iptables[i]))
        stdout = os.popen("iptables -vL -t" + i, 'r')
        res = stdout.read().split('\n')
        printOut(res, 3)
        print 

    print ('{}').format("[+] APPS INSTALLED")
    executeCmd({0:"apt list --installed"}, 1)
    print
    executeCmd({0:"dpkg -l"}, 1)

    print ('{}').format("[+] SERVICES")
    executeCmd({0:"systemctl -l --type service --all"}, 1)

    print ('{}').format("[+] KERNEL MODULES")
    executeCmd({0:"lsmod"}, 1)

    print ('{}').format("[+] ARP")
    executeCmd({0:"arp -a"}, 1)

    print ('{}').format("[+] TRAP")
    executeCmd({0:"trap -l"}, 1)

#    print ('{}').format("[+] HASHES")
#    executeCmd({0:"find / -exec md5sum {} \;"})

if __name__ == "__main__":
    main()
