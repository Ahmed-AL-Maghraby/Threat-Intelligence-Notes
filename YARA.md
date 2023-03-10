
## yara rules  important keywords 

###  - Meta :
   - Can be used to add additional information about the rule, such as author name, description, and version.

### - strings :
   - used to specify the text strings to search for in files.

### - $ :
   - used to assign a variable name to strings.

### - condition : 
   - Specifies the conditions that must be met for the threat to be detected.


##  examples of yara rules

<br>

+ This YARA rule searches for a suspicious string "This string is used in malware" within a file. If the string is found, the rule is triggered.

```yara
rule suspicious_string
{
    strings:
        $suspicious_string = "This string is used in malware"
    condition:
        $suspicious_string
}
```
<br>

+ This YARA rule checks if the file size is greater than 10MB. If the file size is greater than 10MB, the rule is triggered.

```yara

rule suspicious_filesize
{
    meta:
        description = "Detects files larger than 10MB"
    condition:
        filesize > 10MB
}
```
<br>

+ YARA rule for detecting intrusive software using Metasploit:

```yara
rule Metasploit_Hacking_Tool
{
    meta:
        author = "John Doe"
        description = "Detects hacking tools that use Metasploit"
        version = "1.0"
    strings:
        $string1 = "Metasploit"
        $string2 = "exploit"
        $string3 = "payload"
    condition:
        $string1 and ($string2 or $string3)
}
```

+ YARA rule for detecting assembly files:

```yara
rule DLL_Stealer
{
    meta:
        author = "John Doe"
        description = "Detects malware that steals DLLs"
        version = "1.0"
    strings:
        $string1 = "kernel32.dll"
        $string2 = "user32.dll"
        $string3 = "ntdll.dll"
    condition:
        all of them
}
```

<br>


## LOKI Tool

+ Tool Help :
  -  ``python loki.py -h``

+ Upgared tool : 
  -  ``--update``

+ Rules Folder :

  - `` /signature-base ``
+ Run tool :
  - `` ../directory-$ python /Loki/loki.py -p . ``

<br>
<br>
<br>
