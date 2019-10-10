#!/bin/bash
export EDITOR=vi
export PIP_USER=yes
#export PATH=${HOME}/.local/bin:$PATH
alias startwatch="cd ~/github/bots/subwatchbot;/usr/bin/screen -dmS subwatch python3 subwatch.py"
alias watchlog="tail -f ~/github/bots/subwatchbot/bot.log"
alias watchstatus="ps -ef|grep subwatch.py |grep -v grep"
#export LC_ALL="en_US.UTF-8"


BOTDIR="${HOME}/github/bots/subwatchbot"
cd $BOTDIR

export TZ=EST5EDT
BOTPIDFILE="${BOTDIR}/bot.pid"
BOTPID=$(cat ${BOTPIDFILE})

if [ -f ${BOTDIR}/DONOTSTART ]; then
	exit 0
fi

if ! ps -ef |awk '{print $2}' |grep -q ${BOTPID}; then
    	/usr/bin/screen -dmS subwatch python3 -u subwatch.py
else
	echo "Bot running: pid=${BOTPID}" 
	exit 0
fi

