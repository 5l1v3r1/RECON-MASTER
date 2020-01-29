#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#               PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF NETWORKS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import shutil
import os.path
import hashlib
import binascii
import datetime
import fileinput
import linecache
import subprocess
from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print "\nPlease run this python script as root..."
    exit(True)

if len(sys.argv) < 1:
    print "\nUse the command python footprinting.py"
    exit(True)

#BH1 = sys.argv[1]	# NEO4J USERNAME
#BH2 = sys.argv[2]	# NEO4J PASSWORD
BUG = 1			# DEBUG COMMANDS

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create function calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      variable += " "
   return variable

def rpadding(variable,value):
   variable = variable.rstrip("\n")
   while len(variable) < value:
      temp = variable
      variable = "." + temp
   return variable

def dpadding(variable,value):
   test = variable
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      if test == "":
         variable += " "
      else:
         variable += "."
   return variable

def gettime(value):
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = padding(variable, value)
   return variable

def command(command):
   if BUG == 1:
      print colored(command, 'white')
   os.system(command)
   return

def prompt():
   selection = raw_input("\nPress ENTER to continue...")
   return

def display():
   print u'\u2554' + (u'\u2550')*36 + u'\u2566' + (u'\u2550')*33 + u'\u2566' + (u'\u2550')*61 + u'\u2557'
   print u'\u2551' + (" ")*12 + colored("REMOTE SYSTEM",'white') +  (" ")*11 + u'\u2551' + (" ")*10 + colored("SYSTEM SHARES",'white') + (" ")*10 + u'\u2551' + (" ")*21 +  colored("USER INFORMATION",'white') + (" ")*24 + u'\u2551' 
   print u'\u2560' + (u'\u2550')*14 + u'\u2564' + (u'\u2550')*21 + u'\u256C' + (u'\u2550')*12 + u'\u2550' + (u'\u2550')*20 + u'\u256C' + (u'\u2550')*61 + u'\u2563'

   print u'\u2551' + " DNS SERVER   " + u'\u2502',
   if DNSN == "EMPTY              ":
      print colored(DNSN[:19],'yellow'),
   else:
      print colored(DNSN[:19],'blue'),
   print u'\u2551',
   print colored(SH0,'blue'),
   print colored(SHA0,'blue'),
   print u'\u2551',
   print colored(US[0],'blue'),
   print colored(PA[0],'blue'),
   print u'\u2551'

   print u'\u2551' + " LOCAL IP     " + u'\u2502',
   if LIP == "EMPTY              ":
      print colored(LIP[:19],'yellow'),
   else:
      print colored(LIP[:19],'blue'),
   print u'\u2551',
   print colored(SH1,'blue'),
   print colored(SHA1,'blue'),
   print u'\u2551',
   print colored(US[1],'blue'),
   print colored(PA[1],'blue'),
   print u'\u2551'

   print u'\u2551' + " REMOTE IP    " + u'\u2502',
   if TIP == "EMPTY              ":
      print colored(TIP,'yellow'),
   else:
      print colored(TIP,'blue'),
   print u'\u2551' ,
   print colored(SH2,'blue'),
   print colored(SHA2,'blue'),
   print u'\u2551',
   print colored(US[2],'blue'),
   print colored(PA[2],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " PASSWORD     " + u'\u2502',
   if PAS == "EMPTY              ":
      print colored(PAS,'yellow'),
   else:
      print colored(PAS,'blue'),
   print u'\u2551',
   print colored(SH3,'blue'),
   print colored(SHA3,'blue'),
   print u'\u2551',
   print colored(US[3],'blue'),
   print colored(PA[3],'blue'),
   print u'\u2551'

   print u'\u2551' + " NTLM HASH    " + u'\u2502',
   if FRST == "EMPTY              ":
      print colored(FRST[:19],'yellow'),
   else:
      print colored(FRST[:19],'red'),
   print u'\u2551',
   print colored(SH4,'blue'),
   print colored(SHA4,'blue'),
   print u'\u2551',
   print colored(US[4],'blue'),
   print colored(PA[4],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " DOMAIN NAME  " + u'\u2502',
   if HST == "EMPTY              ":
      print colored(HST[:20],'yellow'),
   else:
      print colored(HST[:20],'blue'),
   print u'\u2551',
   print colored(SH5,'blue'),
   print colored(SHA5,'blue'),
   print u'\u2551',
   print colored(US[5],'blue'),
   print colored(PA[5],'blue'),
   print u'\u2551'

   print u'\u2551' + " DOMAIN SID   " + u'\u2502',
   if WGRP == "EMPTY              ":
      print colored(WGRP[:19],'yellow'),
   else:
      print colored(WGRP[:19],'red'),
   print u'\u2551',
   print colored(SH6,'blue'),
   print colored(SHA6,'blue'),
   print u'\u2551',
   print colored(US[6],'blue'),
   print colored(PA[6],'blue'),
   print u'\u2551'
     
   print u'\u2551' + " SHARE NAME   " + u'\u2502',
   if HIP == "EMPTY              ":
      print colored(HIP[:COL1],'yellow'),
   else:
      print colored(HIP[:COL1],'blue'),
   print u'\u2551',
   print colored(SH7,'blue'),
   print colored(SHA7,'blue'),
   print u'\u2551',
   print colored(US[7],'blue'),
   print colored(PA[7],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " IMPERSONATE  " + u'\u2502',
   if POR == "Administrator      ":
      print colored(POR[:COL1],'yellow'),
   else:
      print colored(POR[:COL1],'blue'),
   print u'\u2551',
   print colored(SH8,'blue'),
   print colored(SHA8,'blue'),
   print u'\u2551',
   print colored(US[8],'blue'),
   print colored(PA[8],'blue'),
   print u'\u2551'
      
   print u'\u2551' + " WIN COMMAND  " + u'\u2502',
   if PRM == "'dir -FORCE'       ":
      print colored(PRM[:COL1],'yellow'),
   else:
      print colored(PRM[:COL1],'blue'),
   print u'\u2551',
   print colored(SH9,'blue'),
   print colored(SHA9,'blue'),
   print u'\u2551',
   print colored(US[9],'blue'),
   print colored(PA[9],'blue'),
   print u'\u2551'

   print u'\u2551' + " CURRENT TIME " + u'\u2502',
   if SKEW == 0:
      print colored(PI1[:COL1],'yellow'),
   else:
      print colored(PI1[:COL1],'blue'),
   print u'\u2551',
   print colored(SH10,'blue'),
   print colored(SHA10,'blue'),
   print u'\u2551',
   print colored(US[10],'blue'),
   print colored(PA[10],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " MY DIRECTORY " + u'\u2502',
   if DIR == "WORKAREA           ":
      print colored(DIR[:COL1],'yellow'),
   else:
      print colored(DIR[:COL1],'blue'),
   print u'\u2551',
   print colored(SH11,'blue'),
   print colored(SHA11,'blue'),
   print u'\u2551',
   if US[11] == "Some users are not shown!!":
      print colored(US[11],'red'),
   else:
      print colored(US[11],'blue'),
   print colored(PA[11],'blue'),
   print u'\u2551'

   print u'\u2560' + (u'\u2550')*14 + u'\u2567'+ (u'\u2550')*21  + u'\u2569' + (u'\u2550')*12 + u'\u2550' + (u'\u2550')*20 + u'\u2569' + (u'\u2550')*61 + u'\u2563'

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print u'\u2551' + "(0) Save/Exit          (10) Re/Set    (20) Whois REMOTE IP     (30)                (40)                (50)              (60)       " + u'\u2551'
   print u'\u2551' + "(1) Re/Set DNS SERVER  (11) Re/Set    (21) Host REMOTE IP      (31)                (41)                (51)              (61)       " + u'\u2551'
   print u'\u2551' + "(2) Re/Set LOCAL IP    (12) Re/Set    (22) Dig REMOTE IP       (32)                (42)                (52)              (62)       " + u'\u2551'
   print u'\u2551' + "(3) Re/Set REMOTE IP   (13) IP Route  (23) Fierce REMOTE IP    (33)                (43)                (53)              (63)       " + u'\u2551'
   print u'\u2551' + "(4) Re/Set             (14) ARP Cache (24) DNSEnum REMOTE IP   (34)                (44)                (54)              (64)       " + u'\u2551'
   print u'\u2551' + "(5) Re/Set             (15) IFConfig  (25) Nmblookup REMOTE IP (35)                (45)                (55)              (65)       " + u'\u2551'
   print u'\u2551' + "(6) Re/Set             (16) NetStat   (26) DNSRecon            (36)                (46)                (56)              (66)       " + u'\u2551'
   print u'\u2551' + "(7) Re/Set             (17)           (27)                     (37)                (47)                (57)              (67)       " + u'\u2551'
   print u'\u2551' + "(8) Re/Set             (18)           (28)                     (38)                (48)                (58)              (68)       " + u'\u2551'
   print u'\u2551' + "(9) Re/Set             (19)           (29)                     (39)                (49)                (59)              (69)       " + u'\u2551'
   print u'\u255A' + (u'\u2550')*132 + u'\u255D'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence BroadbentAdres                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("clear")
print "__        _____ _   _   __  __    _    ____ _____ _____ ____      " 
print "\ \      / /_ _| \ | | |  \/  |  / \  / ___|_   _| ____|  _ \     " 
print " \ \ /\ / / | ||  \| | | |\/| | / _ \ \___ \ | | |  _| | |_) |    " 
print "  \ V  V /  | || |\  | | |  | |/ ___ \ ___) || | | |___|  _ <     " 
print "   \_/\_/  |___|_| \_| |_|  |_/_/   \_\____/ |_| |_____|_| \_\    "
print "                                                                  "
print "BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS\n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Boot the system and initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print "[+] Booting - Please wait...\n"

if not os.path.exists("WORKAREA"):		# DEFUALT WORKAREA
   os.mkdir("WORKAREA")
   print "[-] Work area created..."
else:
   print "[-] Work area already exists..."

print "[-] Populating system variables..."

COL1 = 19
COL2 = 31
COL3 = 26
COL4 = 32
COL5 = 15

#PRO  = "/usr/share/doc/python3-impacket/examples/" # IMPACKET LOCATION
LIP  = "10.10.10.xxx       " # LOCAL IP
SKEW = 0                     # TIME ADJUSTED

SH0  = " "*COL5 # SHARE
SH1  = " "*COL5 # SHARE 
SH2  = " "*COL5 # SHARE
SH3  = " "*COL5 # SHARE
SH4  = " "*COL5 # SHARE
SH5  = " "*COL5 # SHARE
SH6  = " "*COL5 # SHARE
SH7  = " "*COL5 # SHARE
SH8  = " "*COL5 # SHARE
SH9  = " "*COL5 # SHARE
SH10 = " "*COL5 # SHARE 
SH11 = " "*COL5 # SHARE

SHA0  = " "*COL5 # SHARE ATTRIBUTE
SHA1  = " "*COL5 # SHARE ATTRIBUTE
SHA2  = " "*COL5 # SHARE ATTRIBUTE
SHA3  = " "*COL5 # SHARE ATTRIBUTE
SHA4  = " "*COL5 # SHARE ATTRIBUTE
SHA5  = " "*COL5 # SHARE ATTRIBUTE
SHA6  = " "*COL5 # SHARE ATTRIBUTE
SHA7  = " "*COL5 # SHARE ATTRIBUTE
SHA8  = " "*COL5 # SHARE ATTRIBUTE
SHA9  = " "*COL5 # SHARE ATTRIBUTE
SHA10 = " "*COL5 # SHARE ATTRIBUTE
SHA11 = " "*COL5 # SHARE ATTRIBUTE


X1   = " "*COL3
X2   = " "*COL4
US   = []
PA   = []
US   = [X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1] # 40 USERNAMES
PA   = [X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2] # 40 PASSWORDS

MAX  = 39
ADD  = 0
ADD2 = 0

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists('config.txt'):
   print "[-] Configuration file not found - using defualt values..."
   DNSN = "EMPTY              " # DNS NAME
   LIP  = "127.0.0.1          " # LOCAL IP
   TIP  = "EMPTY              " # USERNAME
   PAS  = "EMPTY              " # PASSWORD       
   FRST = "EMPTY              " # NTML HASH
   HST  = "EMPTY              " # DOMAIN NAME
   WGRP = "EMPTY              " # DOMAIN SID
   HIP  = "EMPTY              " # CURRENT SHARE
   POR  = "Administrator      " # IMPERSONATE
   PRM  = "'dir -FORCE'       " # WIN COMMAND                                            
   PI1  = "00:00              " # LOCAL TIME    
   DIR  = "WORKAREA           " # DIRECTORY
else:
   print "[-] Configuration file found - restoring saved data...."
   DNSN = linecache.getline('config.txt', 1)
   LIP  = linecache.getline('config.txt', 2)
   TIP  = linecache.getline('config.txt', 3)
   PAS  = linecache.getline('config.txt', 4)
   FRST = linecache.getline('config.txt', 5)
   HST  = linecache.getline('config.txt', 6)
   WGRP = linecache.getline('config.txt', 7)
   HIP  = linecache.getline('config.txt', 8)
   POR  = linecache.getline('config.txt', 9)
   PRM  = linecache.getline('config.txt', 10)
   PI1  = linecache.getline('config.txt', 11)
   DIR  = linecache.getline('config.txt', 12)

   DNSN = padding(DNSN, COL1)
   LIP  = padding(LIP,  COL1)
   TIP  = padding(TIP,  COL1)
   PAS  = padding(PAS,  COL1)
   if FRST[:5] == "EMPTY":
      FRST = padding(FRST, COL1)
   HST  = padding(HST,  COL1)
   if WGRP[:5] == "EMPTY":
       WGRP = padding(WGRP, COL1)
   HIP  = padding(HIP,  COL1)
   POR  = padding(POR,  COL1)
   PRM  = padding(PRM,  COL1)
   PI1  = padding(PI1,  COL1)
   DIR  = padding(DIR,  COL1)

raw_input("\nPlease ENTER key to continue...")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   command("clear")
   PI1 = gettime(COL1)
   display()
   selection=raw_input("Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Save current data to config.txt and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '0':
      command("echo " + DNSN + " > config.txt")
      command("echo " + LIP  + " >> config.txt")
      if TIP.rstrip(" ") == "\"\"":
         command("echo '\"\"' >> config.txt")
      else:
         command("echo " + TIP  + " >> config.txt")     
      if PAS.rstrip(" ") == "\"\"":
         command("echo '\"\"' >> config.txt")
      else:
         command("echo " + PAS  + " >> config.txt")
      command("echo " + FRST.rstrip("\n") + " >> config.txt") 
      command("echo " + HST  + " >> config.txt")  
      command("echo " + WGRP.rstrip("\n") + " >> config.txt")
      command("echo " + HIP  + " >> config.txt")  
      command("echo " + POR  + " >> config.txt")  
      tmp = '\"' + PRM.rstrip(" ") + '\"'
      command("echo " + tmp + " >> config.txt")  
      command("echo " + PI1  + " >> config.txt")  
      command("echo " + DIR  + " >> config.txt")  
      
      os.remove("SECRETS.tmp")
      os.remove("SHARES.tmp")
      os.remove("USERS.tmp")
      os.remove("users.txt")

      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNSN
      DNSN = raw_input("\nPlease enter DNS SERVER name: ")
      if DNSN != "":
         if len(DNSN) < 19:
            DNSN = padding(DNSN, COL1)
         command("echo '" + LIP.rstrip(" ") + "\t" + DNSN.rstrip(" ") + "' >> /etc/hosts")
         print "DNS SERVER " + DNSN.rstrip(" ") + " has been added to /etc/hosts..."
         prompt()
      else:
         DNSN = BAK 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = LIP
      LIP = raw_input("\nPlease enter LOCAL IP address: ")
      if LIP != "":
         padding(LIP, COL1)
      else:
         LIP = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      BAK = TIP
      TIP = raw_input("\nPlease enter REMOTE IP address: ")
      if TIP != "":
         padding(TIP, COL1)
      else:
         TIP = BAK  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      exit(1)   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      command("ip route ")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      command("arp -a")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      command("ifconfig")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      command("netstat - tunp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      exit(1)  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      exit(1)  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      exit(1)  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      command("whois " + LIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      command("host -d " + LIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '22':
      command("dig " + LIP.rstrip(" ") + " afxr")
      command("dig @" + LIP.rstrip(" ") + " -x " + LIP.rstrip(""))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      command("fierce -dns " + LIP.rstrip(" ") + " -prefix /usr/share/wordlists/rockyou.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - dnsenum -enum -f <wordlist> <client domain>
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      command("dnsenum -enum -f /usr/share/wordlists/rockyou.txt " + LIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      command("nmblookup -A " + LIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      command("dnsrecon -d " + LIP.rstrip(" ") + " -g")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Details : 32/64 bit
# Modified: N/A
# ------------------------------------------------------------------------------------- 

   if selection == '27':
      exit()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Details : Anonymous login check.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      exit(1)   

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: 
# -------------------------------------------------------------------------------------

   if selection =='36':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub11bc5814059277a4c697f5536e27beaa
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      exit(1) 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      exit(1)       

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      exit(1)              

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      exit(1)   

#Eof...
