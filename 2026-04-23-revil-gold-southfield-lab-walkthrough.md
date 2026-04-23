---
title: "REvil - GOLD SOUTHFIELD Lab Walkthrough"
date: 2026-04-23 18:00:00 +0200
categories: [CyberDefenders Labs]
tags: [cyberdefenders, threat-hunting, walkthrough]
description: "REvil - GOLD SOUTHFIELD lab walkthrough as a black-box investigation."
media_subpath: /assets/img/posts/revil-gold-southfield-lab-walkthrough/
image:
  path: cover.png
  alt: REvil GOLD SOUTHFIELD lab cover image
---

## Overview

In this post I'll share my walkthrough in REvil - GOLD SOUTHFIELD Lab in splunk
Note: I solved this lab initially without reading the questions then answered them all at once at the end
## Solution

First thing i did was identifying the sourcetypes in the lab using query 
```spl
index=* 
| stats count by sourcetype
```
This led to only one sourcetype which was **REvil** 
It was including Sysmon logs, so searching with the Event IDs for process creation (Event ID 1) 
Query used 
```spl
index=revil  "winlog.event_id"=1 
| stats count by "winlog.event_data.OriginalFileName"
```
This query was used to find the logs with event id equals to 1 - which is process creation - and group them by the name of the file used in this process 
![Event id 1 query result](powershell.png){: w="900" h="500" }
That led to multiple results one of them is **PowerShell.EXE** 
Examining the only result with file is PowerShell.EXE led to an encoded base64 payload 
```c 
RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA==
```
which is decoded to ``` Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();} ``` so this command is iterating for the volume shadow copies and deletes them which indicates that the parent process is a malicious process 
The parent process info are: 
-Process name is **facebook assistant.exe**
-Process path is **C:\Users\Administrator\Downloads\facebook assistant.exe**
-PID is **5348** 
-Hashes are **SHA1=E5D8D5EECF7957996485CBC1CDBEAD9221672A1A,MD5=4D84641B65D8BB6C3EF03BF59434242D,SHA256=B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA,IMPHASH=C686E5B9F7A178EB79F1CF16460B6A18**
![Powershell event result](event.png){: w="900" h="500" }

Now since I got the PID of the malicious process, I used it to find all the events in which this PID was the PID the process itself or its parent using the following query 
```spl 
index=revil
( winlog.event_data.ParentProcessId="5348" OR winlog.event_data.ProcessId="5348")
| table _time winlog.event_data.Image winlog.event_id winlog.event_data.TargetFilename
```
This query is searching for any event with its parent process id or the id of the process itself is equal to **5348** and make it in a table with columns are the time of the event, the image name, event id and the target file name
![PID search result](PID.png){: w="900" h="500" }
This led to 27 events, most of them are dropping the ransom notes file with name **5uizv5660t-readme.txt**
The first important one is the process creation of **facebook assistant.exe** itself then it sets registry with the path **HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-2931289057-395607685-1339121393-500\\Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe**
, it executes the powershell command we discussed earlier and then it started to drop the ransom notes and the process terminated after all of that. 

I didn't find any further events that can help in the investigation.
Now checking the questions of the lab: 
-**Q1-To begin your investigation, can you identify the filename of the note that the ransomware left behind?** 
It was answered already in the investigation, the answer is **5uizv5660t-readme.txt**
-**Q2-After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved**
The answer is **5348**
-**Q3-Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?**
Answer is **C:\Users\Administrator\Downloads\facebook assistant.exe**
-**Q4-Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?**
Answer is **Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}**
-**Q5-As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?**
Answer is **B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA**
-**Q6-One crucial piece remains: identifying the attacker's communication channel. Can you leverage threat intelligence and known Indicators of Compromise (IoCs) to pinpoint the ransomware author's onion domain?**
I had not answered this during the investigation, searching with the malware hash, I found this 
[Tria](https://tria.ge/200624-pdt44nqn6x)
which led to the website needed 
**aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion**

