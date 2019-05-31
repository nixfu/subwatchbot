#!/bin/bash
export EDITOR=vi
export PIP_USER=yes
export PATH=/home/redditbot/.local/bin:$PATH
alias startwatch="cd ~/github/bots/subwatchbot;/usr/bin/screen -dmS subwatch python3 subwatch.py"
alias watchlog="tail -f ~/github/bots/subwatchbot/bot.log"
alias watchstatus="ps -ef|grep subwatch.py |grep -v grep"

BOTDIR="/home/redditbot/github/bots/subwatchbot"
cd $BOTDIR

export TZ=EST5EDT

if ! ps -ef |grep -v grep | grep -q "python3 -u subwatch.py"; then
    	/usr/bin/screen -dmS subwatch python3 -u subwatch.py
else
	echo "Bot running" 
	exit 0
fi

