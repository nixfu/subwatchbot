#!/bin/bash
export EDITOR=vi
export PIP_USER=yes
export PATH=/home/myredditbot/.local/bin:$PATH
alias startwatch="cd ~/github/bots/subwatchbot;/usr/bin/screen -dmS subwatch python3 subwatch.py"
alias watchlog="tail -f ~/github/bots/subwatchbot/bot.log"
alias watchstatus="ps -ef|grep subwatch.py |grep -v grep"

BOTDIR="/home/myredditbot/github/bots/subwatchbot"
cd $BOTDIR

export TZ=EST5EDT

BOTPID=$(cat ${BOTDIR}/bot.pid)

if ! ps -ef |awk '{print $2}' |grep -q ${BOTPID}; then
    	/usr/bin/screen -dmS subwatch python3 -u subwatch.py
else
	echo "Bot running: pid=${BOTPID}" 
	exit 0
fi

