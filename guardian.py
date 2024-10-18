#!/usr/bin/env python3
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
import os, sys, re, shutil;
from glob import glob;
import re;
import signal;
import subprocess;
import datetime;
from collections import Counter;
import logging;
from logging.handlers import RotatingFileHandler;

os.umask(0o077);# default umask => rw- --- ---

# Doc: Another principle exists, instead of blocking requests, it is possible to abuse protocols to make the attacker lag indefinitely: https://nullprogram.com/blog/2019/03/22/
# Doc: https://bencane.com/2013/01/14/mitigating-dos-attacks-with-a-null-or-blackhole-route-on-linux/



####################################################################################################
# v - CONFIGURATION - v
# List of ports to be monitored.
# if TG_WATCH_PORTS_TCP='auto' => TG_WATCH_PORTS_TCP will be generated at with netstat/ss
# It's possible to invert the list of ports by adding an extra ! before the list:
# TG_WATCH_PORTS_TCP='!22,80,443' => banny any access to all ports except on ports 22,80,443
TG_WATCH_PORTS_TCP = os.getenv('WATCH_PORTS_TCP','auto');
TG_WATCH_PORTS_UDP = os.getenv('WATCH_PORTS_UDP','auto');
TG_INTERFACE = os.getenv('INTERFACE','ens3'); # Interface to watch
# List of files to be monitored with the associated filter detector
TG_LOGS_WATCHER = {
	'/var/log/nginx/access.log': 'httpFilter',
	'/var/log/auth.log': 'authSSHFilter',
	'/var/log/messages': 'kernelLog'
};
TG_BAN_LEN = int(str(os.getenv('BAN_DURATION',str(60*30))),10);# Ban duration in seconde (default: 30 minutes)
TG_BAN_INC = int(str(os.getenv('BAN_INCREMENTATION',str(60*5))),10);# Ban duration in case of recurrence in seconde. This time is added according to the following formula: {TG_BAN_LEN}+{Number of ban}*TG_BAN_INC
# ^ - CONFIGURATION - ^
####################################################################################################



TG_RUN_PID = '/var/run/guardian.pid';
TG_BAN = '/var/run/guardian';
TG_LOG = '/var/log/guardian.log';
TG_WHITE_IP = '127.0.0.1';

os.makedirs('/etc/guardian/', exist_ok=True) 
if os.path.exists('/etc/guardian/allow'):
	with open('/etc/guardian/allow','r') as fp:
		TG_WHITE_IP += '\n'+fp.read().replace('\r','');
TG_BLACK_IP = '';
if os.path.exists('/etc/guardian/deny'):
	with open('/etc/guardian/deny','r') as fp:
		TG_BLACK_IP += '\n'+fp.read().replace('\r','');
TG_BANED_IP_COUNTER = {};
# Convert TG_LOGS_WATCHER
tmp = {};
for i in TG_LOGS_WATCHER:
	tmp[i] = {'fp':None, 'reloadFileRotate':True, 'callback':TG_LOGS_WATCHER[i]};
TG_LOGS_WATCHER = tmp;

if TG_WATCH_PORTS_TCP == 'auto':
	with open('/proc/net/tcp','r') as fp:
		TG_WATCH_PORTS_TCP = ['25','53']
		for port in re.findall(r'\s*\d+: 00000000:([a-zA-Z0-9]+)', fp.read()):
			TG_WATCH_PORTS_TCP += [str(int(port,16))]
		TG_WATCH_PORTS_TCP = ','.join(sorted(set(TG_WATCH_PORTS_TCP)))
	if not TG_WATCH_PORTS_TCP:
		raise Exception('Unable to list local open TCP ports');
	TG_WATCH_PORTS_TCP = '!'+TG_WATCH_PORTS_TCP;

if TG_WATCH_PORTS_UDP == 'auto':
	with open('/proc/net/udp','r') as fp:
		TG_WATCH_PORTS_UDP = ['123','53','68']
		for port in re.findall(r'\s*\d+: 00000000:([a-zA-Z0-9]+)', fp.read()):
			TG_WATCH_PORTS_UDP += [str(int(port,16))]
		TG_WATCH_PORTS_UDP = ','.join(sorted(set(TG_WATCH_PORTS_UDP)))
	if not TG_WATCH_PORTS_UDP:
		raise Exception('Unable to list local open UDP ports');
	TG_WATCH_PORTS_UDP = '!'+TG_WATCH_PORTS_UDP;

os.makedirs(TG_BAN, exist_ok=True)


TG_ISTESTREGEXP = 0;

def main():
	global TG_ISTESTREGEXP,TG_RUN_PID, log;
	log = iniLog(__name__, TG_LOG);
	try:
		if len(sys.argv) == 2:
			if sys.argv[1] == 'status' or sys.argv[1] == 'st':
				print('[*] Instance:');
				getProcessInfo();
				print('');
				print('[*] Actualy dropped');
				os.system('ip r | grep -F "blackhole" | sed "s/^/    /"');
				os.system('ip -6 r | grep -F "blackhole" | sed "s/^/    /"');
				print('');
				print('[*] Actualy BLACK listed');
				print('    '+TG_BLACK_IP.replace('\n','\n    '));
				os.system('[ "`/sbin/iptables -nvL INPUT | grep GUARDIAN | wc -l`" -gt 0 ] && /sbin/iptables -nvL INPUT | grep -E \'(GUARDIAN|pkts)\' | sed "s/^/    /"');
				os.system('[ "`/sbin/ip6tables -nvL INPUT | grep GUARDIAN | wc -l`" -gt 0 ] && /sbin/ip6tables -nvL INPUT | grep -E \'(GUARDIAN|pkts)\' | sed "s/^/    /"');

				tmplog = open(TG_LOG, 'r').read()
				print('[*] Most viewed \033[1;31mTCP\033[0m ports');
				z=re.findall('access to TCP port ([0-9]+)', tmplog)
				for port,count in Counter(z).most_common(20):
					print('%05d count on port %s'%(count,port));
				print('[*] Most viewed \033[1;31mUDP\033[0m ports');
				z=re.findall('access to UDP port ([0-9]+)', tmplog)
				for port,count in Counter(z).most_common(20):
					print('%05d count on port %s'%(count,port));
				print('\n');
				currentWeek = datetime.date.today().strftime('%V')
				print('[*] Most viewed \033[1;31mTCP\033[0m ports this week (%s)'%(currentWeek));
				z=re.findall('#'+currentWeek+'&[^\r\n]+ access to TCP port ([0-9]+)', tmplog)
				for port,count in Counter(z).most_common(20):
					print('%05d count on port %s'%(count,port));
				print('[*] Most viewed \033[1;31mUDP\033[0m ports this week (%s)'%(currentWeek));
				z=re.findall('#'+currentWeek+'&[^\r\n]+ access to UDP port ([0-9]+)', tmplog)
				for port,count in Counter(z).most_common(20):
					print('%05d count on port %s'%(count,port));

				print('');
				try:
					print(open(TG_BAN+'.st','r').read());
				except:
					print('[*] Actualy white listed');
					print('    '+TG_WHITE_IP.strip('\r\n\t ').replace('\n','\n    '));
					print('');
					print('[*] List of TCP ports watched:\n    %s'%(TG_WATCH_PORTS_TCP));
					print('[*] List of UDP ports watched:\n    %s'%(TG_WATCH_PORTS_UDP));

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
				print('[+] Install OK');
				sys.exit(0);
			elif sys.argv[1] == 'log':
				os.system('cat '+TG_LOG);
				sys.exit(0);
			elif sys.argv[1] == 'run' or sys.argv[1] == 'start':
				try:
					pid = open(TG_RUN_PID, 'r').read();
					cmd = open('/proc/'+pid+'/cmdline').read();
					if 'daemon' in cmd:
						print('[*] Daemon already exist');
						getProcessInfo();
						sys.exit(0);
				except Exception as e:
					pass;
				os.system(f'setsid {sys.argv[0]} daemon & \n echo "Service up and running"; ps faux | grep -E \'[g]uardian\' | grep -F daemon');
				sys.exit(0);
			elif sys.argv[1] == 'kill' or sys.argv[1] == 'stop' or sys.argv[1] == 'cleanup':
				log.info('[*] Stopping guardian');
				try:
					pid = open(TG_RUN_PID, 'r').read();
					os.kill(int(pid,10),signal.SIGKILL);
					os.remove(TG_RUN_PID);
				except:
					pass;
				clearIpTables();
				if sys.argv[1] == 'cleanup':
					log.info('[*] UnBan all');
					os.system("ip r | grep -F 'blackhole' | awk '{print $2}' | xargs -I '{}' ip r del '{}'");
					os.system("rm -rf -- "+TG_BAN+"*");
					sys.exit(0);
				sys.exit(0);
			elif sys.argv[1] == 'standalone':
				log.info('[*] Standalone mode');

			elif sys.argv[1] == 'daemon':
				log.info('[*] Dameon mode');
				with open(TG_RUN_PID,'w') as fp:
					fp.write(str(os.getpid()));
					fp.flush();
				log.info('Dameon mode');

			elif sys.argv[1] == 'test':
				log.info('[*] Test RegExp');
				TG_ISTESTREGEXP = 1;
				try:
					initIptables();
					for lg in TG_LOGS_WATCHER:
						if os.path.exists(lg):
							log.info(f'Watch log {lg}');
							fp = open(lg, 'r');
							TG_LOGS_WATCHER[lg]['fp'] = fp;
						else:
							log.warning(f'Log {lg} doesn\'t exist. Not watching...');

					while 1:
						for lg in TG_LOGS_WATCHER:
							_eof = False;
							if TG_LOGS_WATCHER[lg]['fp'] != None:
								while not _eof:
									line = TG_LOGS_WATCHER[lg]['fp'].readline();
									if line:
										globals()[TG_LOGS_WATCHER[lg]['callback']](line);
									else:
										_eof = True;
						sleep(0.5);
				except Exception as e:
					log.exception(str(e));
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
		if os.path.exists(lg):
			log.info(f'Watch log {lg}');
			fp = open(lg, 'r');
			fp.seek(0, 2);# Set the cursor to the end
			TG_LOGS_WATCHER[lg]['fp'] = fp;
		else:
			log.warning(f'Log {lg} doesn\'t exist. Not watching...');
			TG_LOGS_WATCHER[lg]['fp'] = None


	log.info('The Guardian is up and running');
	while 1:
		for lg in TG_LOGS_WATCHER:
			_eof = False;
			if TG_LOGS_WATCHER[lg]['fp'] != None:
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


def iniLog( name, logfile, logLevel=logging.INFO ):
	lg = logging.getLogger(name);
	lg.setLevel(logLevel);		
	_formatter = logging.Formatter('[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)3d] %(message)s')
	stdoutHandler = logging.StreamHandler();
	stdoutHandler.setFormatter(_formatter);
	stdoutHandler.setLevel(logLevel);
	lg.addHandler(stdoutHandler);
	# création d'un handler qui va rediriger une écriture du log vers
	# un fichier en mode 'append', avec 7 backup et une taille max de 10Mo
	fileHandler = RotatingFileHandler( logfile, 'a', 1000000*10, backupCount=7 );
	fileHandler.setFormatter(_formatter);
	lg.addHandler(fileHandler);
	return lg;


def getProcessInfo():
	os.system('ps faux | grep -Ei \'[g]uardian\' | grep -F daemon');


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
	log.info(f'Ban IP {ip} with the reason {reason}');
	if ip == '-':
		log.error(f'''Invalid IP ({ip}) for the http module ! In /etc/nginx/nginx.conf put log_format main '$remote_addr - $remote_user [$time_local] "$host" "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time';''');
		return ;
	if ip in listSSHConnexion():
		log.info(f'IP {ip} is connected via SSH. No ban for that IP !');
		return;
	if '\n'+ip+'\n' in TG_WHITE_IP:
		log.info(f'IP {ip} is white listed');
		return;
	if not TG_ISTESTREGEXP:# Si on n'est pas en mode test => on ban
		if not black:
			open(TG_BAN+'/'+ip,'w').close();
		if ':' in ip:
			if iptables:
				runcmd(f'ip6tables -I INPUT 1 ! -i lo -s {ip} -m comment --comment \'[GUARDIAN] {reason}\' -j DROP');
			else:
				runcmd(f'ip -6 r add blackhole "{ip}" >> {TG_LOG} 2>&1');
		else:
			if iptables:
				runcmd(f'iptables -I INPUT 1 ! -i lo -s {ip} -m comment --comment \'[GUARDIAN] {reason}\' -j DROP');
			else:
				runcmd(f'ip r add blackhole "{ip}"', ignoreTxt='RTNETLINK answers: File exists');
	if ip in TG_BANED_IP_COUNTER:
		TG_BANED_IP_COUNTER[ip] += 1;
		log.info(f'IP {ip} has been banned for {TG_BAN_LEN/60 + TG_BANED_IP_COUNTER[ip]*TG_BAN_INC/60} minutes');
	else:
		TG_BANED_IP_COUNTER[ip] = 1;
		log.info(f'IP {ip} has been banned for {TG_BAN_LEN/60} minutes');


def unban( ip ):
	log.info(f'unBan IP {ip} after {(time() - os.stat(os.path.join(TG_BAN,ip)).st_mtime)/60} minutes');
	if ':' in ip:
		runcmd(f'ip -6 r del "{ip}"');
	else:
		runcmd(f'ip r del "{ip}"');
	os.remove(TG_BAN+'/'+ip);


def loadTimer4Ban():
	global TG_BANED_IP_COUNTER;
	log.info('Loading ban timer for each IP...');
	data = '';
	with open(TG_LOG, 'r') as fp:
		data = fp.read();
	TG_BANED_IP_COUNTER = Counter(re.findall(r'Ban IP ([^ ]+) with the reason', data));


def cleanup():
	now = time();
	for ip in os.listdir(TG_BAN):
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
			ban(line.split(' ')[0], f'{i} found in http request <{line.strip("\r\n\t ")}>');


def authSSHFilter( line ):
	if 'sshd' not in line:
		return ;
	if 'Invalid user' in line:
		ban(line.split(' Invalid user ')[-1].split(' from ')[-1].split(' ')[0], f'invalid SSH user in <{line.strip("\r\n\t ")}>');


def kernelLog( line ):
	if '[GUARDIAN]' not in line:
		return;
	ip = line.split(' SRC=')[-1].split(' ')[0];
	port = line.split(' DPT=')[-1].split(' ')[0];
	if 'PROTO=TCP' in line:
		ban(ip, 'access to TCP port '+port);
	else:
		ban(ip, 'access to UDP port '+port);


_reloadFileRotate = {};
def reloadFileRotate( fp ):
	size = os.stat(fp.name).st_size;
	name = fp.name;
	stat = os.stat(name);
	stat = str(stat.st_dev)+'-'+str(stat.st_ino);
	if name in _reloadFileRotate and (_reloadFileRotate[name]['size'] > size or _reloadFileRotate[name]['inode'] != stat ):
		log.info(f'Log rotate detected on {name}');
		fp.close();
		fp = open(name, 'r');
	_reloadFileRotate[name] = {'size':size, 'inode':stat};
	return fp;


def clearIpTables():
	log.info('[*] Cleaning iptables rules');
	runcmd('iptables -F GUARDIAN');
	runcmd('ip6tables -F GUARDIAN');
	stdout,stderr = runcmd('iptables -nvL INPUT --line-numbers');
	stdout = re.findall(r'\s+([0-9]+)[^\r\n]+ GUARDIAN \\*', stdout)
	stdout.reverse()
	for row in stdout:
		runcmd('iptables -D INPUT '+row);
	runcmd('iptables -X GUARDIAN');

	stdout,stderr = runcmd('ip6tables -nvL INPUT --line-numbers');
	stdout = re.findall(r'\s+([0-9]+)[^\r\n]+ GUARDIAN \\*', stdout)
	stdout.reverse()
	for row in stdout:
		runcmd('ip6tables -D INPUT '+row);
	runcmd('ip6tables -X GUARDIAN');

	log.info('[*] Enable logging martians packets');
	with open('/proc/sys/net/ipv4/conf/all/log_martians', 'w') as fp:
		fp.write('1\n');
	with open('/proc/sys/net/ipv4/conf/default/log_martians', 'w') as fp:
		fp.write('1\n');


def initIptables():
	log.info('Init iptables');
	log.info(f'List of TCP ports watched {TG_WATCH_PORTS_TCP}');
	log.info(f'List of UDP ports watched {TG_WATCH_PORTS_UDP}');
	clearIpTables();
	runcmd('iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "GUARDIAN"');
	runcmd('ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "GUARDIAN"');

	runcmd('iptables -N GUARDIAN');
	runcmd('ip6tables -N GUARDIAN');
	runcmd('iptables -A GUARDIAN -j LOG --log-prefix "[GUARDIAN]" -m comment --comment "GUARDIAN"');
	runcmd('iptables -A GUARDIAN -j DROP');
	runcmd('ip6tables -A GUARDIAN -j LOG --log-prefix "[GUARDIAN]" -m comment --comment "GUARDIAN"');
	runcmd('ip6tables -A GUARDIAN -j DROP');

	invert = '';
	ports = TG_WATCH_PORTS_TCP;
	if TG_WATCH_PORTS_TCP.startswith('!'):
		ports = TG_WATCH_PORTS_TCP[1:];
		invert = '!';
	runcmd(f'iptables  -A INPUT -i {TG_INTERFACE} -p tcp -m multiport {invert} --dports {ports} -j GUARDIAN -m comment --comment "GUARDIAN"');
	runcmd(f'ip6tables -A INPUT -i {TG_INTERFACE} -p tcp -m multiport {invert} --dports {ports} -j GUARDIAN -m comment --comment "GUARDIAN"');

	invert = '';
	ports = TG_WATCH_PORTS_UDP;
	if TG_WATCH_PORTS_UDP.startswith('!'):
		ports = TG_WATCH_PORTS_UDP[1:];
		invert = '!';
	runcmd(f'iptables  -A INPUT -i {TG_INTERFACE} -p udp -m multiport {invert} --dports {ports} -j GUARDIAN -m comment --comment "GUARDIAN"');
	runcmd(f'ip6tables -A INPUT -i {TG_INTERFACE} -p udp -m multiport {invert} --dports {ports} -j GUARDIAN -m comment --comment "GUARDIAN"');

	log.info('Disable logging martians packets');
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
		fp.write(f'[*] List of TCP ports watched:\n    {TG_WATCH_PORTS_TCP}\n');
		fp.write(f'[*] List of UDP ports watched:\n    {TG_WATCH_PORTS_UDP}\n');


def runcmd(cmd, echo=False, ignoreTxt=''):
	if echo:
		log.debug('[*] BASH: '+cmd);
		os.system(cmd);
		return ;
	stdout,stderr = subprocess.Popen(str(cmd), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate();
	stdout = stdout.decode('utf8');
	stderr = stderr.decode('utf8');
	if stderr.strip('\r\n\t '):
		if ignoreTxt and (ignoreTxt in stdout or ignoreTxt in stderr):
			return (stdout,stderr);
		log.info('[*] BASH: '+cmd);
		log.debug(f'[*] BASH ret: {stdout} / {stderr}');
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

if __name__ == "__main__":
	main();

