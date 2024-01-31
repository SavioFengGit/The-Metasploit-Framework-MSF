# The-Metasploit-Framework-MSF-
Let's introduce The Metasploit Framework (MSF)
# Introduction of Framework
## Metasploit
<img src="meta.png" width=60% height="auto"><br>
The metasploit framework is a tool that allows you to test the security of your network and systems by simulating attacks and exploiting vulnerabilities. It is a collaboration between the open source community and Rapid7, a security company. The metasploit framework has a library of exploits, payloads, and utilities that you can use to launch attacks, gain access, and maintain persistence on your targets. You can also write your own modules and scripts to customize your attacks. <br>
The architecture of metasploit is shown below <br>
<img src="moduli.jpg" width=60% height="auto"><br>

### We quickly explain these modules:
1. **Exploit**: An exploit module is a piece of code that takes advantage of a vulnerability in a target system or application. It can execute arbitrary commands, install malware, or create a backdoor for future access.
2. **Payload**: A payload module is a piece of code that runs on the target system after the exploit succeeds. It can perform various actions, such as opening a shell, downloading a file, or adding a user.
3. **Encoder**: An encoder module is a piece of code that transforms a payload into a different format to avoid detection by antivirus or firewall software. It can use various techniques, such as encryption, obfuscation, or polymorphism.
4. **Nop**: A nop module is a piece of code that does nothing. It is used to fill the space between the exploit and the payload, or to align the payload to a specific address. It can also be used to bypass certain security mechanisms, such as stack cookies or address space layout randomization (ASLR).
5. **Auxiliary**: An auxiliary module is a piece of code that performs a supporting task, such as scanning, fingerprinting, or sniffing. It can also be used to test the target system for vulnerabilities, or to gather information for later exploitation.

### The Payload can be staged or not:
 - **A payload non staged** (or stageless) is a single piece of code that contains everything needed to get a reverse shell callback. It is larger in size and more complex than a payload staged, but it does not require any additional communication with the attacker.
 - **A payload staged** (or stager) is a small piece of code that connects to the attacker and downloads a second piece of code (or stage) that contains the actual functionality. It is smaller in size and simpler than a payload non staged, but it requires an extra interaction with the attacker. <br>
 
A payload staged can be more stealthy and flexible than a payload non staged, as it can evade detection by antivirus or firewall software and download different stages depending on the situation. However, a payload non staged can be more reliable and faster than a payload staged, as it does not depend on the availability of the attacker or the network connection. <br>
<img src="msfconsole.png" width=60% height="auto"><br>

## Usage: msfconsole [options]

## Common options:
    -E, --environment ENVIRONMENT    Set Rails environment, defaults to RAIL_ENV environment variable or 'production'

## Database options:
    -M, --migration-path DIRECTORY   Specify a directory containing additional DB migrations
    -n, --no-database                Disable database support
    -y, --yaml PATH                  Specify a YAML file containing database settings

## Framework options:
    -c FILE                          Load the specified configuration file
    -v, -V, --version                Show version

## Module options:
        --[no-]defer-module-loads    Defer module loading unless explicitly asked
    -m, --module-path DIRECTORY      Load an additional module path

## Console options:
    -a, --ask                        Ask before exiting Metasploit or accept 'exit -y'
    -H, --history-file FILE          Save command history to the specified file
    -l, --logger STRING              Specify a logger to use (StdoutWithoutTimestamps, TimestampColorlessFlatfile, Flatfile, Stderr, Stdout)
        --[no-]readline
    -L, --real-readline              Use the system Readline library instead of RbReadline
    -o, --output FILE                Output to the specified file
    -p, --plugin PLUGIN              Load a plugin on startup
    -q, --quiet                      Do not print the banner on startup
    -r, --resource FILE              Execute the specified resource file (- for stdin)
    -x, --execute-command COMMAND    Execute the specified console commands (use ; for multiples)
    -h, --help                       Show this message

# My Personal List of modules for Enumeration:
## FTP 21:
	• use auxiliary/scanner/ftp/ftp_version
	set RHOSTS 192.51.147.3
	exploit (vede la versione ftp)
	• use auxiliary/scanner/ftp/ftp_login
	set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
	set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
	set RHOSTS
	exploit (brute force per le credenziali)
	• use auxiliary/scanner/ftp/anonymous (vede se supporta l'accesso anonimo)

## Samba 445
	• msfconsole 
	use auxiliary/scanner/smb/smb_version 
	set RHOSTS 192.126.66.3 
 exploit

## Apache 80
	1. auxiliary/scanner/http/http_version (identifica la versione del server web e del protocollo HTTP usati dal target)
	2. auxiliary/scanner/http/http_header (recupera e visualizza le intestazioni HTTP della risposta del server web)
	3. auxiliary/scanner/http/robots_txt (cerca e analizza il file robots.txt del server web, che contiene le indicazioni per i crawler sui contenuti da indicizzare o escludere)
	4. auxiliary/scanner/http/brute_dirs (identifica l’esistenza di directory interessanti sul server web tramite una forza bruta basata su permutazioni di caratteri)
	5. auxiliary/scanner/http/dir_scanner (identifica l’esistenza di directory interessanti sul server web tramite una forza bruta basata su una lista di parole)
	6. auxiliary/scanner/http/dir_listing (verifica se il server web permette la visualizzazione dell’elenco dei file nelle directory)
	7. auxiliary/scanner/http/files_dir (cerca e scarica i file presenti nelle directory del server web)
	8. auxiliary/scanner/http/http_put (verifica se il server web permette il caricamento di file tramite il metodo HTTP PUT)
	9. auxiliary/scanner/http/http_login (prova a effettuare il login sul server web tramite una forza bruta basata su una lista di credenziali)
	10. auxiliary/scanner/http/apache_userdir_enum (enumera le directory degli utenti sul server web Apache tramite il modulo mod_userdir)


## MYSQL 3306
	1. auxiliary/scanner/mysql/mysql_version (identifica la versione del server MySQL e del protocollo usati dal target)
	2. auxiliary/scanner/mysql/mysql_login (prova a effettuare il login sul server MySQL tramite una forza bruta basata su una lista di credenziali)
	3. auxiliary/admin/mysql/mysql_enum (enumera le informazioni sul server MySQL, come i database, le tabelle, le colonne e i dati)
	4. auxiliary/admin/mysql/mysql_sql (esegue una query SQL arbitraria sul server MySQL)
	5. auxiliary/scanner/mysql/mysql_file_enum (cerca e scarica i file presenti sul server MySQL tramite la funzione LOAD_FILE)
	6. auxiliary/scanner/mysql/mysql_hashdump (recupera e visualizza gli hash delle password degli utenti del server MySQL)
	7. auxiliary/scanner/mysql/mysql_schemadump (recupera e visualizza lo schema del database del server MySQL)
	8. auxiliary/scanner/mysql/mysql_writable_dirs (identifica le directory scrivibili sul server MySQL tramite la funzione INTO OUTFILE)

## SSH 22
	• use auxiliary/scanner/ssh/ssh_login 
	set RHOSTS 192.245.211.3 
	set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt 
	set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 
	set STOP_ON_SUCCESS true 
	set VERBOSE true 
	exploit (brute force)

## SMTP 25
	• msfconsole 
	use auxiliary/scanner/smtp/smtp_enum 
	set RHOSTS 192.80.153.3 
	exploit (enumera gli utenti rispetto alla wordlist di metasploit esistenti)












