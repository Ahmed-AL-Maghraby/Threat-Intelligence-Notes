
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

## LOKI Tool

python loki.py -h

--update

signature-base

 ../directory-$ python /Loki/loki.py -p .
