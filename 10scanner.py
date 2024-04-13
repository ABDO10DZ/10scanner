import requests
import sys
import urllib3
from portscan import PortScan
import socket
import time
import whois
import dns.resolver
import json
from bs4 import BeautifulSoup
import re
from printy import printy,escape
urllib3.disable_warnings()
output = None
secs = 0

info = []
Dir = "/wp-content/plugins/"		# default plugins dir 
themeDir = "/wp-content/themes/"
readme = "/readme.txt"				# readme file , could be readme.md too
target = None
list = None

username_list = "def-users.txt"
password_list = "def-pass.txt"
def who(target):									# whois 
	w=whois.whois(target,0)
	w.expiration_date
	print(w)
	return
def nmap_scan(target):								# port scan
	if target.startswith("http://") == True or target.startswith("https://"):
		url = re.compile(r"https?://(www\.)?")
		target = url.sub('', target).strip().strip('/')	

	ip = socket.gethostbyname(target)
	port_range = '1,1-65535' # all Possible ports will be scaned
	print("[*] Luanching port scan on ",target,":",ip," ports:",port_range)
	ip = socket.gethostbyname(target)
	scanner = PortScan(ip, port_range, thread_num=500, show_refused=False, wait_time=1, stop_after_count=True)
	open_port_discovered = scanner.run()  # <----- actual scan
	for port in open_port_discovered:
		printy(f"[nB][FOUND]:@ {port}")
	
	print("[*] Luanching CMS scan in 5 Seconds ...")
	time.sleep(5)
	return

def log(file,data):
	if file == None:
		return
	with open(file, "a") as myfile:
		myfile.write(data+"\n")
	return

def request(target,headers,body,isJson=True,timeout=3,method=0):
	try:
		response = [None,None,None]
		r = None
		if method == 0:
			r = requests.get(target,headers=headers,data=body,timeout=int(timeout),verify=False)
		else :
			r = requests.post(target,headers=headers,json=body,timeout=int(timeout),verify=False)	# json post
		response[0] = r.headers			# return headers , detect webserver/phpv 

		response[1] = r.text			# return response
		response[2]	= r.status_code		# http status code
		return response
	except Exception as e:
		print("Exception:",e)
		pass
	return False
def check(Target,timeout):							# brute forcer
	try:
		user_agent = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'}
		r = requests.get(Target,headers=user_agent,timeout=int(timeout),verify=False)
		if r.status_code == 200:
			r.close()
			return True
	except Exception as e:
		print("Exception:",e)	# if had an exception 
		pass
	return False
def plugins(target,lista="wp-plugins.lst"):
	if target.startswith("http://") is False and target.startswith("https://") is False:
		target = "http://" + target
	printy(f"starting [nB]Plugins@ scan...")
	time.sleep(5)
	plugins_file = open(lista, 'r')  # https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/main/wp-plugins.lst (wipe all /wp-content/plugins/ and /readme.txt) - leave only plugin name (easy with find and replace)
	plugins = plugins_file.readlines()
	for plugin in plugins:
		plugin = plugin.strip()
		print("[*] checking ",target+Dir+plugin)
		if(check(target+Dir+plugin+"/",secs)):
			if (check(target+Dir+plugin+readme,secs)):
				printy(f"[nB][FOUND]:@ {plugin} [gB][readme.txt]@ {target+Dir+plugin+readme}")
				log(output,target+Dir+plugin+readme)
			else :
				print(f"[nB][FOUND]:@ {plugin} [rB][readme.txt]@ {target+Dir+plugin}")
				log(output,target+Dir+plugin)
	return
def themes(target,lista="wp-themes.lst"):
	if target.startswith("http://") is False and target.startswith("https://") is False:
		target = "http://" + target
	themes_file = open(lista, 'r')
	themes = themes_file.readlines()
	printy(f"starting [nB]themes@ scan...")
	for theme in themes:
		theme = theme.strip()
		print("[*] checking ",target+themeDir+theme)
		if(check(target+themeDir+theme+"/",secs)):
			if (check(target+themeDir+theme+readme,secs)):
				printy(f"[nB][FOUND]:@ {theme} [gB][readme.txt]@ {target+themeDir+theme+readme}")
				log(output,target+themeDir+theme+readme)
			else :
				printy(f"[nB][FOUND]:@ {theme} [rB][readme.txt]@ {target+themeDir+theme}")
				log(output,target+themeDir+theme)
	return
def login(target,usernames,passwords):
	return
def public_vulnerability_map(target,version,is_in_core=True,plugin=None,theme=None):
	return
def Ai_vulnerability_map(target,path):
	return
def dirmap(target,list):
	return

def detect_cms(target):
	response = check(target,None)
	if "wp-admin" in response[1]  or "wp-admin/admin-ajax.php":
		info[0] = "wordpress"
		info[1] = "php"
	if "apache" in response[0] or ("apache" in response[1] and 404 == response[2]):
		info[2] = "Apache"
	elif "nginx" in response[0] or ("nginx" in response[1] and 404 == response[2]):
		info[2] = "Nginx"
	elif "litespeed" in response[0] or ("litespeed" in response[1] and 404 == response[2]):
		info[2] = "LiteSpeed" 
	else:
		info[2] = "Unknown"

	return

def lookup(target):
	printy("Luanching [nB]records lookup@")
	name_server = '8.8.8.8'
	ADDITIONAL_RDCLASS = 65535
	request = dns.message.make_query(target, dns.rdatatype.ANY)
	request.flags |= dns.flags.AD
	request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,dns.rdatatype.OPT, create=True, force_unique=True)       
	response = dns.query.udp(request, name_server)
	print("lookup response:",response)
	return
def domains(target):
	#soon
	return
def find_subdomains(domain):
	subs = None
	try:
		api_key="9GpEVaaVOtzP8z5sNUJ6JOq1sPhBV17H"					# SecurityTrails API key, u can use ur own
		headers = {
        	"APIKEY": api_key,
        	"Accept": "application/json",
			"User-Agent": "10"
    	}
		url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains?children_only=false&include_inactive=true"
		response = request(url,headers,None)[1]
		Jdata = json.loads(response)
		subdomains = Jdata.get('subdomains', [])
		for sub in subdomains:
			sub += "." + target
			printy(f'[nb][FOUND]:@ {sub}')

	except Exception as e:
		printy(f"[rB]Exception[subdomains]:@ {e}")
	return subs

def get_info(address):
	who(address)
	lookup(target)
	domains(target)
	find_subdomains(target)
	nmap_scan(target)
	return True

def main():
	if len(sys.argv)<4:
		print(sys.argv[0],"-u <url> -t <timeout>  -o <output> (other options)\n\n")

		print("-a/--all  \t  full scan ")
		print("\n Controlling parameters")
		print("-u/--url \t ", "<url/ip> \t ", "Target ip address or domain name E.g = www.target.com .")
		print("-t/--timeout \t ", "<seconds> \t ","connection timeout in seconds E.g = 3 .")
		print("-o/--output \t ","<file> \t ","output log file , where u want save tool output E.g = /tmp/test.log")
		print("-th/--threads \t ","<number> \t ","threads number so the tool will work faster as threads u set E.g = 20")
		print("\n mapping parameters")
		print("-br/--bruteforce \t ","<type> <lists>\t ","brute force types = plugins/themes/login lists = usernames/password/themes/plugins")
		print("\n-v/--vulnerability-mapping \t ","<cms> \t ","vulnerabilities mapping including 2 techniques below")
		print("-aiv/--ai-vulnerability-map \t ","<cms> \t ","mapping vulnerabilities through AI instructions . cms = local path to cms")
		print("-pv/--pub-vulnerability-map \t ","<N/A> \t ","mapping public vulnerabilities .")
		print("\ninfo gathering parameters")
		print("-d/--dirmap  \t ","<N/A> \t ","dirmapping")
		print("-i/--info \t ", "<N/A> \t ","cms detect/webserver/language/subdomains/domains...")

		sys.exit(0)
	# modes 
	generic = False
	
	info = False			# info gathering

	vulnerability_mapping = False # both below
	Ai_vulnerability_map = False # Ai vuln mapping 
	public_vulnerability_map = False # pub vuln mapping
	
	dirmap = False
	btype = None 					# contains strings plugins|themes|login
	global target,username_list,password_list,list,secs,output
	for x in range(len(sys.argv)):
		if sys.argv[x] == "-u" or sys.argv[x] == "--url":
			target = sys.argv[x+1]
		elif sys.argv[x] == "-t" or sys.argv[x] == "--timeout":
			secs = sys.argv[x+1] # timeout connect
		elif sys.argv[x] == "-o" or sys.argv[x] == "--output":
			output = sys.argv[x+1]
		elif sys.argv[x] == "-th" or sys.argv[x] == "--threads":
			threads = sys.argv[x+1]
		elif sys.argv[x] == "-br" or sys.argv[x] == "--bruteforce":
			btype = sys.argv[x+1]
			if btype == "plugins" or btype == "themes":
				list = sys.argv[x+2]
			elif btype == "login":
				username_list = sys.argv[x+2]
				password_list = sys.argv[x+3]

			list = sys.argv[x+2]
		elif sys.argv[x] == "-v" or sys.argv[x] == "--vulnerability-mapping":
			cmspath = sys.argv[x+1]
			vulnerability_mapping = True
		elif sys.argv[x] == "-aiv" or sys.argv[x] == "--ai-vulnerability-map":
			cmspath = sys.argv[x+1]
			Ai_vulnerability_map = True
		elif sys.argv[x] == "-pv" or sys.argv[x] == "--pub-vulnerability-map":
			public_vulnerability_map = True
		elif sys.argv[x] == "-d" or sys.argv[x] == "--dirmap":
			dirmap = True
		elif sys.argv[x] == "-i" or sys.argv[x] == "--info":
			info = True
		elif sys.argv[x] == "-a" or sys.argv[x] == "--all":
			generic = True

	print("luanching scan on :",target,"timeout:",secs,"output:",output)
	time.sleep(5)
	if generic == True or info == True:
		get_info(target)

	# brute force types 
	if btype == "plugins" or generic == True:
		if list == None:
			plugins(target)
		else:
			plugins(target,list)
	elif btype == "themes":
		themes(target,list)
	elif btype == "login":
		login(target,username_list,password_list)


	return
if __name__=="__main__":
	try:
		main()
	except KeyboardInterrupt:
		print ('\nInterrupted : Quiting...')
		sys.exit(0)
