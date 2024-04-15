10scanner is command line python code webapps vulenrability scanner 
v1 (Beta version ill updated with full functionality as described in next updates):
<br></br><img src="https://i.ibb.co/zsMvV4z/10scanner.png" width="600" height="200"><br></br>
* Notice : this still under dev , now all u can do is -a for full scan in the progress of codes i reached (info gathering ,plugins bruteforce)
```
python -m pip install -r req.txt
python 10scanner.py -u target.com -a
```
* generic info including 
```
 - whois,nslookup,portscan, cms detection
 - subdomains,domains hosted on same server , webserver , language used ,sitmaps&robots.
 - off indexed directories , dirmapping . 
```
* bruteforce 
```
* themes,plugins bruteforce 
* login bruteforce 
```
* vulnerability mapping ( <a href="https://wp-cli.org/"> WP-CLI</a> / <a href="https://docs.joomla.org/J4.x:CLI_Update">J4-CLI</a> are required !)
```
 * CMS old vulnerabilities
  - checking current core & plugin versions and look for potential public flaw 
 * CMS 0days vulnerabilities with AI algorithms help to discover new flaws in CMS plugins 
  - requires localhost installed same target CMS , will auto install the plugins and check for potential Syntaxes that lead to a vulnerability exploitation
```
 still under dev currently but not farway to release a beta version .
 - could be add webpanel work related with 10scanner commandline.

this tool may simplify ur work and short time for u , but it sure manual testing is always best.
<br><br><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FABDO10DZ%2F10scanner&count_bg=%23F00444&title_bg=%23251212&icon=&icon_color=%23BCAEAE&title=views&edge_flat=false"/></a>
