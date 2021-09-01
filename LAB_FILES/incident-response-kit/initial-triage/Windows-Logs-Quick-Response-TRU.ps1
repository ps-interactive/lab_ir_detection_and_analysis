

# Demo1: Research Globomantics
<# 
Find domains on domaintools
 Lookup domians on VT to look for abuse of that domain.

www.virustotal.com

Shodan lookup what infrastructe is exposed and begin to use this as the target list!

Use tools to lookup compromised credentials.  Know what the attackers know.
 - haveibeenpwned.org domain lookup with api using AMASS?
 - grayscan?
 - Shodan
All has to be passive, you don't have permission to pentest globomantics.
 Build asset, vulnerability and credential list. EXCEL Sheets!

#>


#Module: Preparation:

# Demo2: Preparation
<# Open AMZN Mate IR desktop
Open LAB_FILES in explorer.
Show structured files.
Show Tools organized by phase
Bring up powershell script to show how it is automated using portable tools in the same folder. 
Preparation means thinking through every possible scenario and being prepared as much as possible for each of them. Automation is your friend, adding your Incident Reponse Playbooks as automated actions is exactly what you should be striving to do at a technical level.

python3 -m httpserver to host

Show from victim 2 box how you can the access the tools.

#>


# Module: Validating the Events Initial Triage

# Demo3: Yep this is ransomware.
<# Ransomware makes this easy.
There is a letter, write the domain down.
There are inidicators and unique names, write those down!
There is a popup with base64, copy tha base 64 and reverse it.
Write the name of the consoles down.
Validate what files are compromised, ENCYRPTED is it really encrypted?
What folders?
#>

#What do you know? Now enact that playbook. You prepared for this!

# Demo4: Initial Triage!
# This is certainly ransomware run that play boook.


## Start the timer, and record your actions.
captains_log($entry, $datapath){
    $datetime = Get-Date 
    $timezone = (Get-TimeZone).DisplayName
    $stardate = "Captains Log Entry, Startdate: $datetime $timezone \n"
    $stardate| out-file -Append -FilePath ./$datapath/master-station-log.txt
    $entry | oute-file -Append -FilePath ./$datapath/master-station-log.txt
    write-host "Captains log entry complete." -ForegroundColor Green
}

# Have to store things somewhere, ideally this is all launched from and recorded to your external media.
    ## Computer name as folder
    $name = $env:computername
    $domain = $env:USERDOMAIN
    $datapath = "$name-$domain"
    new-item -Name $datapath -Path . -ItemType directory
    #creates master station log to record all your actions
    get-date >> ./data/master-station-log.txt
    Get-TimeZone >> ./$datapath/master-station-log.txt
    Get-NetIPInterface >> $datapath/master-station-log.txt
    Get-NetIPAddress = >> $datapath/master-station-log.txt
    #records all your activity
    start-transcript -Path ./$datapath/master-station-log.txt -Append
    #  


    ## Memory Dump - Do a quick memory pull we will look more at this later.
    mempdump.exe $datapath/$computername-memorydump.dmp 
    captains_log "Took full memory image." $datapath
    
    ##memoryze
    ##msiexec /a MemoryzeSetup
    ##memoryDD.bat




    ## Get file hash & Time Stamp of Ransome note.
    captains_log "Desktop has ransom note file, grabbing properties and hash as potential IOC" $datapath
    $note_file_details = get-itemproperty -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt; $note_file_details
    $note_file_details | out-file -path $datapath/IOC-ransom-note.txt -append
    $filehash = get-filehash -Path C:\Users\Administrator\Desktop\invincibleironcat.txt; $filehash
    $filehash | out-file -path $datapath/IOC-ransom-note.txt -append
    copy-item -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt  $datapath
    ### Take a guess here to scope and look for this file name/hash throughout the file system.
    get-childitem c:\ | select-string -pattern "theinvincibleironcat" #this version hits the user folder.
    captains_log "IOC - Found ransom notes in all affected directories with the same name and hash only in c:\Users\*. This can be used to look for this acitivity acrosss the enterprise for scoping."

    ## Dump network connection
    ##net connections but then use tcpview and portmon to properly catch beaconing
    captains_log "Running network inspection to look for expected network beaconing behavior related to popup." $datapath
    $netConn = get-nettcpconnection; $netConn
    netstat -anob
    $netconn | export-clixml -Path $datapath/netconn.xml
    $netconn | out-file -Path $datapath/netconn.txt
    ### May or may not catch connection information.
    ## tcpview & portmon
    tcpvcon64.exe -a /accepteula

    ## 

# Identify network activity to resolved hello.iamironcat.com & find process

    # Dump and Analyze Process Information
    $procs = Get-Process; $procs #find process name to use as IOC
    $procs |out-file -path $datapath/processes.txt
    #WMIC get specific process information based on PID found in get-process info.
    wmic query all format html
    procexp64.exe
    #Procexp process explorer to inspect this process and understand its tcp activity!

#tcpview & portmon
    

#DEMO: Use IOC's to find other devices.

## Asset list from ARP table, layer 2
## Asset list from Active Directory Pull 
    Get-adcomputers -filter *
foreach ($c in $computers) {
    get-childitem -Path #if note file ending in ENCRYPTED or HASH matches
    Get-Process #if process like ironcatwuzhere
    get-nettcpconnection #if port like 8080 but doesn't come back in line with the other behavior!
}


#Module: Intel

# Demo: Malware Intel

## Strings

## Google Strings


## Domain Information - clean domain

## Virus Total - find old sample

## Run on anyruns - not a lot of results

## Atomic indicators
#hash of exe to be used to find other exe!


#Module: Host Collection

## Now you have more time to collect a Triage Image --> this is not the full disk image.
systeminfo

## DNS Cache
$dnsCache = Get-DnsClientCache
$dnsCache
$dnsCache  | Export-Clixml -Path $datapath/dnscache.xml
$dnsCache | out-file $datapath/dnscache.txt
### Host File

## ARP Cache
$arpCache  = Get-netnieghbor | select *
$arpCache
$arpCache  | Export-Clixml -Path $datapath/arpcache.xml
$arpCache | out-file $datapath/arpcache.txt

#routing profile
$routeTable = Get-NetRoute
$routeTable 
$routeTable | Export-Clixml -Path $datapath/routetable.xml
$routeTable | out-file $datapath/routetable.txt

#Firewall rules

# users
net user
lusrmgr
net local group administrators
net group administrators
psloggedon64.exe
loggedonsessions.exe
#get-adusers

net use

#services
sc query
wmic service list config

#autoruns

#scheduled tasks
schtasks

#disk information
volumeid64.exe
diskmon.exe
ntfsinfo.exe

#additonal process info
listdll.exe
handle.exe


#event logs
#wevutil qe security /f:text
#logs

new-item -type directory winevent_logs

copy-item -Recurse -path C:\Windows\System32\Winevt\Logs\ -Destination ./winevent_logs

copy-item -recurse -path C:\Windows\System32\LogFiles\ -Destination ./winevent_logs

#### see cleared events this is one of your first clues!
get-winevent    #501


#Autoruns
#portmon -> random port! sendback to file find the other ports!

##Logonsessions

##Pendmove

## portmon again different port listening!

##Other Files Use Hash to find original file location. System32

# Full Disk Image




#Module: Network Collection
#Demo: Network Collection 
## Windows Victim Network Connection & Wireshark Analysis
 rawpcap.exe $datapath/$computername-init-pcap.pcap # doesn't require install of separate dll
 captains_log "Initial dump of 1 Minute of Packet Capture Created"


## Targeted Network Collection: HTTP Traffic just to hello.iamironcat.com & 

## Transfer Network Information
scp 


## Surricata Analysis with Current Threats
suricata

##Inbound http traffic to the specified ports would indicate .....attacker activity!
zeek -r pcap
## Inspect logs with zeek cut conn log specifically
zeekcut









# Network Dump
https://www.netresec.com/?page=rawcap
rawpcap.exe

# Dump memory for later analysis with volatility with procdump

procdump.exe 







#






# FW Rules


# Autoruns

# pipelist

#procmon

#procexp


#portmon









# Network Collection 

# Host Collection