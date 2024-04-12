import requests
import sys
import urllib3
from portscan import PortScan
import socket
import time
import whois
import dns.resolver
urllib3.disable_warnings()
output = "output.txt"
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
def NSlookUp(target):								# NSlookup currently 
	import dns.resolver
	records= ["NS","SRV","PTR","TXT","SOA","A","DNSKEY","DS","APL","DHCID","CERT","NSEC","HIP","ALIAS","NAPTR","CNDSKEY","AFSDB","DNAME","CAA","AAAA","CNAME","URLFWD"]
	for record in records:
		answers =dns.resolver.resolve(target, "NS")
		print(record,"dns lookup")
		for rdata in answers:
    			print ('Host', rdata.to_text()) #rdata.exchange, 'has preference', rdata.preference)
		break
def nmap_scan(target):								# port scan 
	ip = socket.gethostbyname(target)
	port_range = '1,1-65535' # all Possible ports will be scaned
	print("[*] Luanching port scan on ",target,":",ip," ports:",port_range)
	ip = socket.gethostbyname(target)
	scanner = PortScan(ip, port_range, thread_num=500, show_refused=False, wait_time=1, stop_after_count=True)
	open_port_discovered = scanner.run()  # <----- actual scan
	for port in open_port_discovered:
		print("PORT \t ", port , " \t open")
	
	print("[*] Luanching CMS scan in 5 Seconds ...")
	time.sleep(5)
	return

def log(file,data):									# log
	with open(file, "a") as myfile:
		myfile.write(data+"\n")
	return

def request(target,body,timeout=3,ua="10",method=0):
	response = [None,None,None]
	r = None
	if method == 0:
		r = requests.get(target,headers=ua,data=body,timeout=int(timeout),verify=False)
	else :
		r = requests.post(target,headers=ua,json=body,timeout=int(timeout),verify=False)	# json post
	response[0] = r.headers 
	response[1] = r.text
	response[2]	= r.status_code
	return response
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
def plugins(target,list="wp-plugins.lst"):
	plugins_file = open(list, 'r')  # https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/main/wp-plugins.lst (wipe all /wp-content/plugins/ and /readme.txt) - leave only plugin name (easy with find and replace)
	plugins = plugins_file.readlines()
	log(output,"enum plugins started \n")
	for plugin in plugins:
		plugin = plugin.strip()
		print("[*] checking ",target+Dir+plugin)
		if(check(target+Dir+plugin+"/",secs)):
			if (check(target+Dir+plugin+readme,secs)):
				print("[+] Found :",plugin,"readme.txt readable :",target+Dir+plugin+readme)
				log(output,target+Dir+plugin+readme)
			else :
				print("[+] Found :", plugin , "readme.txt missed/unreadable :",target+Dir+plugin)
				log(output,target+Dir+plugin)
	return
def themes(target,list="wp-themes.lst"):
	themes_file = open(list, 'r')  # https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/main/wp-plugins.lst (wipe all /wp-content/plugins/ and /readme.txt) - leave only plugin name (easy with find and replace)
	themes = themes_file.readlines()
	log(output,"enum themes started \n")
	for theme in themes:
		theme = theme.strip()
		print("[*] checking ",target+themeDir+theme)
		if(check(target+themeDir+theme+"/",secs)):
			if (check(target+themeDir+theme+readme,secs)):
				print("[+] Found :",theme,"readme.txt readable :",target+themeDir+theme+readme)
				log(output,target+themeDir+theme+readme)
			else :
				print("[+] Found :", theme , "readme.txt missed/unreadable :",target+themeDir+theme)
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
def get_info(address):
	who(address)
	NSlookUp(address)
	nmap_scan(address)
	return True
def subdomains(target):
	return
def domains(target):
	return
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
	generic = True 			# defualt true (if this true all the rest will be ignored even false)
	
	info = False			# info gathering

	vulnerability_mapping = False # both below
	Ai_vulnerability_map = False # Ai vuln mapping 
	public_vulnerability_map = False # pub vuln mapping
	
	dirmap = False
	btype = None 					# contains strings plugins|themes|login
	global target,username_list,password_list,list,secs,output
	for x in range(len(sys.argv)):
		if sys.argv[x] == "-u" or sys.argv == "--url":
			target = sys.argv[x+1]
		elif sys.argv[x] == "-t" or sys.argv == "--timeout":
			secs = sys.argv[x+1] # timeout connect
		elif sys.argv[x] == "-o" or sys.argv == "--output":
			output = sys.argv[x+1]
		elif sys.argv[x] == "-th" or sys.argv == "--threads":
			threads = sys.argv[x+1]
		elif sys.argv[x] == "-br" or sys.argv == "--bruteforce":
			btype = sys.argv[x+1]
			if btype == "plugins" or btype == "themes":
				list = sys.argv[x+1]
			elif btype == "login":
				username_list = sys.argv[x+2]
				password_list = sys.argv[x+3]

			list = sys.argv[x+2]
		elif sys.argv[x] == "-v" or sys.argv == "--vulnerability-mapping":
			cmspath = sys.argv[x+1]
			vulnerability_mapping = True
		elif sys.argv[x] == "-aiv" or sys.argv == "--ai-vulnerability-map":
			cmspath = sys.argv[x+1]
			Ai_vulnerability_map = True
		elif sys.argv[x] == "-pv" or sys.argv == "--pub-vulnerability-map":
			public_vulnerability_map = True
		elif sys.argv[x] == "-d" or sys.argv == "--dirmap":
			dirmap = True
		elif sys.argv[x] == "-i" or sys.argv == "--info":
			info = True
		elif sys.argv[x] == "-a" or sys.argv == "--all":
			generic = True
		
	print("luanching scan on :",target,"timeout:",secs,"output:",output)
	time.sleep(5)
	if generic == True or info == True:
		get_info(target)

	# brute force types 
	if btype == "plugins":
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