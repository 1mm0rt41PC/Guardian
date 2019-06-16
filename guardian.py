#!/usr/bin/python
#coding: utf8
# The Guardian - A simple script that whatch for unusual tcp/http/ssh activity and ban ip via routing
#
# Filename: guardian.py
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
from time import sleep, time, strftime;
import os, sys, re;
from glob import glob;
import re;
import subprocess;
from collections import Counter;

os.umask(0o077);# default umask => rw- --- ---

# Doc: Another principle exists, instead of blocking requests, it is possible to abuse protocols to make the attacker lag indefinitely: https://nullprogram.com/blog/2019/03/22/
# Doc: https://bencane.com/2013/01/14/mitigating-dos-attacks-with-a-null-or-blackhole-route-on-linux/



####################################################################################################
# v - CONFIGURATION - v
TG_ETH = 'ens3';# Interface to watch
# List of ports to be monitored.
# if TG_WATCH_PORTS='auto' => TG_WATCH_PORTS will be generated at with netstat/ss
# It's possible to invert the liste of ports by adding an extra ! before the list:
# TG_WATCH_PORTS='!22,80,443' => banny any access to all ports except on ports 22,80,443
TG_WATCH_PORTS = 'auto';

# List of files to be monitored with the associated filter detector
TG_LOGS_WATCHER = {
	'/var/log/nginx/access.log': 'httpFilter',
	'/var/log/auth.log': 'authSSHFilter',
	'/var/log/messages': 'kernelLog'
};
TG_BAN_LEN = 60*30;# Ban duration in seconde (default: 30 minutes)
TG_BAN_INC = 60*5;# Ban duration in case of recurrence in seconde. This time is added according to the following formula: {TG_BAN_LEN}+{Number of ban}*TG_BAN_INC
# ^ - CONFIGURATION - ^
####################################################################################################



TG_RUN_PID = '/var/run/guardian.pid';
TG_BAN = '/var/run/guardian';
TG_LOG = '/var/log/guardian.log';
TG_DATE_FORMAT = '%Y/%m/%d #%U& %H:%M:%S';
TG_WHITE_IP = '127.0.0.1';
if os.path.exists('/etc/guardian.allow'):
	with open('/etc/guardian.allow','r') as fp:
		TG_WHITE_IP += '\n'+fp.read().replace('\r','');
TG_BLACK_IP = '';
if os.path.exists('/etc/guardian.deny'):
	with open('/etc/guardian.allow','r') as fp:
		TG_BLACK_IP += '\n'+fp.read().replace('\r','');
TG_BANED_IP_COUNTER = {};
# Convert TG_LOGS_WATCHER
tmp = {};
for i in TG_LOGS_WATCHER:
	tmp[i] = {'fp':None, 'reloadFileRotate':True, 'callback':TG_LOGS_WATCHER[i]};
TG_LOGS_WATCHER = tmp;

if TG_WATCH_PORTS == 'auto':
	try:
		stdout,stderr = subprocess.Popen(r"(/bin/echo -e '25\n53'; ss -lntu | grep -Fi 'LISTEN' | grep -vF '127.0.0.1' | grep -vF '::1' | awk '{print $5}' | sed 's/\*://g' | sed 's/://g') | sort -u -n | paste -sd ',' -", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate();
		stdout = stdout.decode('utf8').strip('\r\n\t ');
		TG_WATCH_PORTS = stdout;
		if not TG_WATCH_PORTS:
			raise Exception(stdout+'\n'+stderr.decode('utf8').strip('\r\n\t '));
		TG_WATCH_PORTS = '!'+TG_WATCH_PORTS;
	except Exception as e:
		print('[!] Unable to get the list off allowed ports: '+str(e));
		sys.exit(2);
try:
	stdout,stderr = subprocess.Popen(r"ip addr show "+TG_ETH+" > /dev/null 2>&1 && echo 1 || echo 0", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate();
	stdout = stdout.decode('utf8').strip('\r\n\t ');
	if '0' in stdout:
		raise Exception('Interface '+TG_ETH+' doesn\'t exist !');
except Exception as e:
	print('[!] Error while checking interface '+TG_ETH+': '+str(e));
	sys.exit(1);

os.system('mkdir -p "%s"'%(TG_BAN));


TG_ISTESTREGEXP = 0;

def main():
	global TG_ISTESTREGEXP,TG_RUN_PID;
	try:
		if len(sys.argv) == 2:
			if sys.argv[1] == 'status' or sys.argv[1] == 'st':
				print('[*] Instance');
				os.system('echo -n "NB instance: "; ps faux | grep -E \'[g]uardian\' | grep -F daemon | wc -l');
				os.system('ps faux | grep -E \'[g]uardian\' | grep -F daemon | sed "s/^/    /"');
				print('');
				print('[*] Actualy dropped');
				#print('    '+('\n'.join(glob(TG_BAN+'/*'))).replace('\n','\n    '));
				os.system('ip r | grep -F "blackhole" | sed "s/^/    /"');
				os.system('ip -6 r | grep -F "blackhole" | sed "s/^/    /"');
				print('');
				print('[*] Actualy BLACK listed');
				print('    '+TG_BLACK_IP.replace('\n','\n    '));
				os.system('[ "`/sbin/iptables -nvL INPUT | grep GUARDIAN | wc -l`" -gt 0 ] && /sbin/iptables -nvL INPUT | grep -E \'(GUARDIAN|pkts)\' | sed "s/^/    /"');
				os.system('[ "`/sbin/ip6tables -nvL INPUT | grep GUARDIAN | wc -l`" -gt 0 ] && /sbin/ip6tables -nvL INPUT | grep -E \'(GUARDIAN|pkts)\' | sed "s/^/    /"');
				print('[*] Most viewed ports');
				os.system(r'''grep -F 'access to port' %TG_LOG% | awk '{print $13}' | sort -n | uniq -c | awk '{printf("    %05d count on port %d\n", $1, $2)}' | sort -r 2>/dev/null| head -n 30'''.replace('%TG_LOG%',TG_LOG));
				print('[*] Most viewed ports this week');
				os.system(r'''grep -F 'access to port' %TG_LOG% | grep -F '#%WEEK%°' | awk '{print $13}' | sort -n | uniq -c | awk '{printf("    %05d count on port %d\n", $1, $2)}' | sort -r 2>/dev/null| head -n 30 | tee /tmp/New-top-ports.log'''.replace('%TG_LOG%',TG_LOG).replace('%WEEK%',strftime('%U')));
				print('[*] Most viewed ports last week');
				os.system(r'''grep -F 'access to port' %TG_LOG% | grep -F '#%WEEK%°' | awk '{print $13}' | sort -n | uniq -c | awk '{printf("    %05d count on port %d\n", $1, $2)}' | sort -r 2>/dev/null| head -n 30'''.replace('%TG_LOG%',TG_LOG).replace('%WEEK%',str(int(strftime('%U'),10)-1)));
				print('[*] Evolution between this week and last week');
				os.system(r'''grep -F 'access to port' %TG_LOG% | grep -F '#%WEEK%°' | awk '{print $13}' | sort -n | uniq -c | awk '{printf("    %05d count on port %d\n", $1, $2)}' | sort -r 2>/dev/null > /tmp/Old-top-ports.log'''.replace('%TG_LOG%',TG_LOG).replace('%WEEK%',str(int(strftime('%U'),10)-1)));
				statsEvolution();
				print('[*] Evolution between this week and all time logs');
				os.system(r'''grep -F 'access to port' %TG_LOG% | awk '{print $13}' | sort -n | uniq -c | awk '{printf("    %05d count on port %d\n", $1, $2)}' | sort -r 2>/dev/null > /tmp/Old-top-ports.log'''.replace('%TG_LOG%',TG_LOG));
				statsEvolution();
				os.remove('/tmp/New-top-ports.log');
				os.remove('/tmp/Old-top-ports.log');

				print('');
				try:
					print(open(TG_BAN+'.st','r').read());
				except:
					print('[*] Actualy white listed');
					print('    '+TG_WHITE_IP.strip('\r\n\t ').replace('\n','\n    '));
					print('');
					print('[*] List of ports watched:\n    %s'%(TG_WATCH_PORTS));

				sys.exit(0);
			elif sys.argv[1] == 'install':
				os.system('cp -f %s /usr/local/bin/guardian'%(os.path.realpath(__file__)));
				os.system('chmod u=rwx,go=- %s'%(os.path.realpath(__file__)));
				os.system('chown root:root %s'%(os.path.realpath(__file__)));
				os.system('chmod u=rwx,go=- /usr/local/bin/guardian');
				os.system('chown root:root /usr/local/bin/guardian');
				with open('/etc/cron.hourly/guardian','w') as fp:
					fp.write('#!/bin/bash\n');
					fp.write('/usr/local/bin/guardian run\n');
				os.system('chmod ugo=rx /etc/cron.hourly/guardian');
				open('/etc/systemd/system/guardian.service', 'w').write(systemd);
				os.system('chmod ugo=r /etc/systemd/system/guardian.service');
				os.system('systemctl enable guardian.service');
				os.system('systemctl daemon-reload');
				open('/etc/init.d/guardian', 'w').write(initd);
				os.system('chmod ugo=rx /etc/init.d/guardian');
				print('Install OK');
				sys.exit(0);
			elif sys.argv[1] == 'log':
				os.system('cat '+TG_LOG);
				sys.exit(0);
			elif sys.argv[1] == 'run' or sys.argv[1] == 'start':
				try:
					pid = open(TG_RUN_PID, 'rb').read();
					cmd = open('/proc/'+pid+'/cmdline').read();
					if 'daemon' in cmd:
						print('[*] Daemon already exist');
						os.system('ps faux | grep -E \'[g]uardian\' | grep -F daemon');
						sys.exit(0);
				except Exception as e:
					pass;
				os.system('setsid %s daemon &'%(sys.argv[0]));
				os.system('echo -n "NB instance: "; ps faux | grep -E \'[g]uardian\' | grep -F daemon | wc -l');
				os.system('ps faux | grep -E \'[g]uardian\' | grep -F daemon');
				sys.exit(0);
			elif sys.argv[1] == 'kill' or sys.argv[1] == 'stop' or sys.argv[1] == 'cleanup':
				print('[*] Stopping guardian');
				os.system('echo -n "NB instance: "; ps faux | grep -E \'[g]uardian\' | grep -F daemon | wc -l');
				os.system('ps faux | grep -E \'[g]uardian\' | grep -F daemon');
				os.system('ps faux | grep -E \'[g]uardian\' | grep -F daemon | awk \'{print $2}\' | xargs -I "{}" kill -9 "{}"');
				try:
					os.remove(TG_RUN_PID);
				except:
					pass;
				print('[*] Cleaning iptables rules');
				os.system('iptables -X; iptables -F; ip6tables -X; ip6tables -F');
				print('[*] Enable logging martians packets');
				with open('/proc/sys/net/ipv4/conf/all/log_martians', 'w') as fp:
					fp.write('1\n');
				with open('/proc/sys/net/ipv4/conf/default/log_martians', 'w') as fp:
					fp.write('1\n');
				if sys.argv[1] == 'cleanup':
					print('[*] UnBan all');
					os.system("ip r | grep -F 'blackhole' | awk '{print $2}' | xargs -I '{}' ip r del '{}'");
					os.system("rm -rf -- "+TG_BAN+"*");
					sys.exit(0);
				sys.exit(0);
			elif sys.argv[1] == 'standalone':
				print('[*] Standalone mode');

			elif sys.argv[1] == 'daemon':
				print('[*] Dameon mode');
				sys.stdout = open(TG_LOG, 'a+');
				sys.stderr = sys.stdout;
				with open(TG_RUN_PID,'wb') as fp:
					fp.write(str(os.getpid()));
					fp.flush();
				print('[%s] '%(strftime(TG_DATE_FORMAT))+'*'*100);
				print('[%s] Dameon mode'%(strftime(TG_DATE_FORMAT)));
				sys.stdout.flush();

			elif sys.argv[1] == 'test':
				print('[*] Test RegExp');
				TG_ISTESTREGEXP = 1;
				try:
					initIptables();
					for lg in TG_LOGS_WATCHER:
						print('[%s] Watch log %s'%(strftime(TG_DATE_FORMAT),lg));
						fp = open(lg, 'r');
						TG_LOGS_WATCHER[lg]['fp'] = fp;

					while 1:
						for lg in TG_LOGS_WATCHER:
							_eof = False;
							while not _eof:
								line = TG_LOGS_WATCHER[lg]['fp'].readline();
								if line:
									globals()[TG_LOGS_WATCHER[lg]['callback']](line);
								else:
									_eof = True;
						sleep(0.5);
				except Exception as e:
					import traceback;
					print(str(e));
					traceback.print_exc();
					import pdb; pdb.set_trace();

			else:
				raise Exception('');
		elif len(sys.argv) == 3:
			if sys.argv[1] == 'unban':
				unban(sys.argv[2]);
				sys.exit(0);
			raise Exception('');
		else:
			raise Exception('');
	except Exception as e:
		print('[*] '+str(e));
		print('[*] Usage:');
		print('[*]     status/st: show dropped/white-listed ip');
		print('[*]     unban <ip>: UnBan an ip');
		print('[*]     cleanup: UnBan all ip');
		print('[*]     run: run guardian into a new process');
		print('[*]     kill/stop: kill all guardian');
		print('[*]     install: install in the cron');
		print('[*]     log: show logs');
		print('[*]     test: Test RegExp');
		print('[*]     standalone/daemon: run in standalone or in daemon mode');
		sys.exit(0);

	initIptables();
	for lg in TG_LOGS_WATCHER:
		print('[%s] Watch log %s'%(strftime(TG_DATE_FORMAT),lg));
		fp = open(lg, 'r');
		fp.seek(0, 2);# Set the cursor to the end
		TG_LOGS_WATCHER[lg]['fp'] = fp;


	print('[%s] The Guardian is up and running'%(strftime(TG_DATE_FORMAT)));
	sys.stdout.flush();
	while 1:
		for lg in TG_LOGS_WATCHER:
			_eof = False;
			if 'reloadFileRotate' in TG_LOGS_WATCHER[lg]:
				TG_LOGS_WATCHER[lg]['fp'] = reloadFileRotate(TG_LOGS_WATCHER[lg]['fp']);
			while not _eof:
				line = TG_LOGS_WATCHER[lg]['fp'].readline();
				if line:
					globals()[TG_LOGS_WATCHER[lg]['callback']](line);
				else:
					_eof = True;
		cleanup();
		sleep(1);


def statsEvolution():
	sNew = open('/tmp/New-top-ports.log','rb').read().decode('utf8').replace('\r','').strip('\r\n\t ').split('\n');
	sOld = open('/tmp/Old-top-ports.log','rb').read().decode('utf8').replace('\r','').strip('\r\n\t ').split('\n');
	try:
		for i in range(0,len(sNew)):
			# 00796 count on port 23
			sNew[i] = sNew[i].strip('\r\n\t ').split(' ')[4];
	except:
		pass;
	try:
		for i in range(0,len(sOld)):
			sOld[i] = sOld[i].strip('\r\n\t ').split(' ')[4];
	except:
		pass;
	for iNewPos in range(0,len(sNew)):
		try:
			posOld = sOld.index(sNew[iNewPos]);
			if posOld > iNewPos:
				print('    %s (\033[32m%d\033[00m)'%(sNew[iNewPos], posOld-iNewPos));
			elif posOld < iNewPos:
				print('    %s (\033[31m%d\033[00m)'%(sNew[iNewPos], posOld-iNewPos));
			else:
				print('    %s (-)'%(sNew[iNewPos]));
		except:
			print('    %s (\033[32m%s\033[00m)'%(sNew[iNewPos], 'NEW'));


def listSSHConnexion():
	global TG_WHITE_IP;
	stdout,stderr = runcmd(r"w -h -i | awk '{print $3}'");
	ret = stdout.strip('\r\n\t ').split('\n');
	TG_WHITE_IP = '\n'+TG_WHITE_IP.strip('\r\n\t ')+'\n';
	for ip in ret:
		if '\n'+ip+'\n' not in TG_WHITE_IP:
			TG_WHITE_IP += ip+'\n';
	logStatus();
	return ret;


def ban( ip, reason, black=False, iptables=False ):
	global TG_ISTESTREGEXP;
	print('[%s] Ban IP %s with the reason %s'%(strftime(TG_DATE_FORMAT),ip,reason));
	if ip == '-':
		print('''[%s] \033[31;1mInvalid IP (%s) for the http module !\033[0m In /etc/nginx/nginx.conf put log_format main '$remote_addr - $remote_user [$time_local] "$host" "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time';'''%(strftime(TG_DATE_FORMAT),ip));
		return ;
	if ip in listSSHConnexion():
		print('[%s] IP %s is connected via SSH. No ban for that IP !'%(strftime(TG_DATE_FORMAT),ip));
		sys.stdout.flush();
		sys.stderr.flush();
		return;
	if '\n'+ip+'\n' in TG_WHITE_IP:
		print('[%s] IP %s is white listed'%(strftime(TG_DATE_FORMAT),ip));
		sys.stdout.flush();
		sys.stderr.flush();
		return;
	if not TG_ISTESTREGEXP:# Si on n'est pas en mode test => on ban
		if not black:
			open(TG_BAN+'/'+ip,'w').close();
		if ':' in ip:
			if iptables:
				runcmd('ip6tables -I INPUT 1 -i %s -s %s -m comment --comment \'%s\' -j DROP'%(TG_ETH, ip, '[GUARDIAN] '+reason));
			else:
				runcmd('ip -6 r add blackhole "%s" >> %s 2>&1'%(ip, TG_LOG));
		else:
			if iptables:
				runcmd('iptables -I INPUT 1 -i %s -s %s -m comment --comment \'%s\' -j DROP'%(TG_ETH, ip, '[GUARDIAN] '+reason));
			else:
				runcmd('ip r add blackhole "%s"'%(ip), ignoreTxt='RTNETLINK answers: File exists');
	if ip in TG_BANED_IP_COUNTER:
		TG_BANED_IP_COUNTER[ip] += 1;
		print('[%s] IP %s has been banned for %d minutes'%(strftime(TG_DATE_FORMAT),ip,TG_BAN_LEN/60 + TG_BANED_IP_COUNTER[ip]*TG_BAN_INC/60));
	else:
		TG_BANED_IP_COUNTER[ip] = 1;
		print('[%s] IP %s has been banned for %d minutes'%(strftime(TG_DATE_FORMAT),ip,TG_BAN_LEN/60));
	sys.stdout.flush();
	sys.stderr.flush();


def unban( ip ):
	print('[%s] unBan IP %s after %d minutes'%(strftime(TG_DATE_FORMAT),ip,(time() - os.stat(os.path.join(TG_BAN,ip)).st_mtime)/60));
	if ':' in ip:
		runcmd('ip -6 r del "%s"'%(ip));
	else:
		runcmd('ip r del "%s"'%(ip));
	runcmd('rm -f -- "%s"'%(TG_BAN+'/'+ip));
	sys.stdout.flush();
	sys.stderr.flush();


def loadTimer4Ban():
	global TG_BANED_IP_COUNTER;
	print('[%s] Loading ban timer for each IP...'%(strftime(TG_DATE_FORMAT)));
	data = '';
	with open(TG_LOG, 'r') as fp:
		data = fp.read();
	TG_BANED_IP_COUNTER = Counter(re.findall(r'Ban IP ([^ ]+) with the reason', data));


def cleanup():
	now = time();
	for ip in os.listdir(TG_BAN):
		#Ban IP %s
		if os.stat(os.path.join(TG_BAN,ip)).st_mtime < now - TG_BAN_LEN:
			if ip in TG_BANED_IP_COUNTER:
				if os.stat(os.path.join(TG_BAN,ip)).st_mtime < now - (TG_BAN_LEN + TG_BANED_IP_COUNTER[ip]*TG_BAN_INC):
					unban(ip);
			else:
				unban(ip);


_httpFilter = [
	r'\x', r'%00', r'" 400 1350 "', r'..%2f', '../', 'POST http://', 'POST https://', 'GET http://', 'GET https://', 'HEAD http://', 'HEAD https://',
	' "TRACE ', ' "CONNECT ',
	' "sqlmap/', 'sqlmap.org', 'xp_cmdshell', 'INFORMATION_SCHEMA',
	# nmap
	' Nmap ','nice%20ports', 'GET /nmaplowercheck', 'GET /.git/HEAD',
	#
	'/xampp',
	'/wp/',
	'/wordpress',
	'/webadmin',
	'/w00tw00t',
	'/typo3',
	'/status',
	'/SQlite',
	'/pma',
	'/phpmyadm',
	'/phpmanager',
	'/mysql',
	'/muieblackcat',
	'/myadmin',
	'/msd',
	'/login',
	'/joomla',
	'/jmx',
	'/jenkins',
	'/cgi',
	'/nmap',
	'/xampp',
];
def httpFilter( line ):
	for i in _httpFilter:
		#if i[0] == '*':# regexp
		#	pass;
		if i.lower() in line.lower():
			ban(line.split(' ')[0], '%s found in http request <%s>'%(i,line.strip('\r\n\t ')));


def authSSHFilter( line ):
	if 'sshd' not in line:
		return ;
	if 'Invalid user' in line:
		ban(line.split(' Invalid user ')[-1].split(' from ')[-1].split(' ')[0], 'invalide SSH user in <%s>'%(line.strip('\r\n\t ')));


def kernelLog( line ):
	if '[IPTABLES]' not in line:
		return;
	ip = line.split(' SRC=')[-1].split(' ')[0];
	port = line.split(' DPT=')[-1].split(' ')[0];
	ban(ip, 'access to port '+port);


_reloadFileRotate = {};
def reloadFileRotate( fp ):
	size = os.stat(fp.name).st_size;
	name = fp.name;
	stat = os.stat(name);
	stat = str(stat.st_dev)+'-'+str(stat.st_ino);
	if name in _reloadFileRotate and (_reloadFileRotate[name]['size'] > size or _reloadFileRotate[name]['inode'] != stat ):
		print('[%s] Log rotate detected on %s'%(strftime(TG_DATE_FORMAT),name));
		fp.close();
		fp = open(name, 'r');
	_reloadFileRotate[name] = {'size':size, 'inode':stat};
	return fp;


def initIptables():
	print('[%s] Init iptables'%(strftime(TG_DATE_FORMAT)));
	print('[%s] List of ports watched %s'%(strftime(TG_DATE_FORMAT),TG_WATCH_PORTS));
	runcmd('iptables -X; iptables -F; ip6tables -X; ip6tables -F');
	runcmd('iptables -A INPUT -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT'%(TG_ETH));
	invert = '';
	ports = TG_WATCH_PORTS;
	if TG_WATCH_PORTS.startswith('!'):
		ports = TG_WATCH_PORTS[1:];
		invert = '!';
	runcmd('iptables -A INPUT -i %s -p tcp -m multiport %s --dports %s -j LOG --log-prefix "[IPTABLES]"'%(TG_ETH,invert,ports));
	runcmd('ip6tables -A INPUT -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT'%(TG_ETH));
	runcmd('ip6tables -A INPUT -i %s -p tcp -m multiport %s --dports %s -j LOG --log-prefix "[IPTABLES]"'%(TG_ETH,invert,ports));
	print('[%s] Disable logging martians packets'%(strftime(TG_DATE_FORMAT)));
	with open('/proc/sys/net/ipv4/conf/all/log_martians', 'w') as fp:
		fp.write('0\n');
	with open('/proc/sys/net/ipv4/conf/default/log_martians', 'w') as fp:
		fp.write('0\n');
	if TG_BLACK_IP.strip('\r\n\t '):
		for ip in TG_BLACK_IP.strip('\r\n\t ').split('\n'):
			ban( ip, 'BLACK LISTED', True, True );
	loadTimer4Ban();


def logStatus():
	with open(TG_BAN+'.st', 'w') as fp:
		fp.write('[*] Actualy white listed\n');
		fp.write('    '+TG_WHITE_IP.strip('\r\n\t ').replace('\n','\n    ')+'\n');
		fp.write('\n');
		fp.write('[*] List of ports watched:\n    %s\n'%(TG_WATCH_PORTS));


def runcmd(cmd, echo=False, ignoreTxt=''):
	if echo:
		print('[*] BASH: %s'%(cmd));
		os.system(cmd);
		return ;
	stdout,stderr = subprocess.Popen('%s'%(cmd), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate();
	stdout = stdout.decode('utf8');
	stderr = stderr.decode('utf8');
	if stderr.strip('\r\n\t '):
		if ignoreTxt and (ignoreTxt in stdout or ignoreTxt in stderr):
			return (stdout,stderr);
		print('[*] BASH: %s'%(cmd));
		print('[*] BASH ret: %s %s'%(stdout,stderr));
	return (stdout,stderr);






systemd = r'''
[Unit]
Description=The Guardian
After=network.target auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/guardian run
ExecStop=/usr/local/bin/guardian stop
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
Alias=guardian.service
'''.strip('\r\n\t ');
initd = r'''
#! /bin/sh

### BEGIN INIT INFO
# Provides:			 guardian
# Required-Start:		 $remote_fs $syslog
# Required-Stop:		$remote_fs $syslog
# Default-Start:		2 3 4 5
# Default-Stop:
# Short-Description:	The Guardian
### END INIT INFO

set -e

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin"

case "$1" in
	start|reload|force-reload|try-restart|restart)
		/usr/local/bin/guardian stop
		/usr/local/bin/guardian run
		;;
	stop)
		/usr/local/bin/guardian stop
		;;
	status|st)
		/usr/local/bin/guardian st
		;;
	log)
		/usr/local/bin/guardian log
		;;
	*)
		log_action_msg "Usage: /etc/init.d/guardian {start|stop|reload|force-reload|restart|try-restart|status|st|log}" || true
		exit 1
esac
exit 0
'''.strip('\r\n\t ');

main();

