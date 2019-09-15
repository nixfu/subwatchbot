#!/usr/bin/python3 -u

# =============================================================================
# IMPORTS
# =============================================================================
import re
import configparser
import logging
import logging.handlers
import time
import os
import sys
from enum import Enum
import praw
import prawcore
import operator
import random
import yaml
import re
import requests
import sqlite3
import pprint
import json


# =============================================================================
# GLOBALS
# =============================================================================
# Reads the config file
config = configparser.ConfigParser()
config.read("bot.cfg")

Settings = {}
Settings = {s: dict(config.items(s)) for s in config.sections()}
Settings['SubConfig'] = {}


ENVIRONMENT = config.get("BOT", "environment")
DEV_USER_NAME = config.get("BOT", "dev_user")
RUNNING_FILE = "bot.pid"

LOG_LEVEL = logging.INFO
#LOG_LEVEL = logging.DEBUG
LOG_FILENAME = Settings['Config']['logfile']
LOG_FILE_INTERVAL = 2
LOG_FILE_BACKUPCOUNT = 5
LOG_FILE_MAXSIZE = 5000 * 256

logger = logging.getLogger('bot')
logger.setLevel(LOG_LEVEL)
#log_formatter = logging.Formatter( '%(levelname)-8s:%(funcName)-10s-%(lineno)4d-%(asctime)s - %(message)s')
#log_formatter = logging.Formatter( '%(levelname)-8s:%(lineno)4d-%(asctime)s - %(message)s')
log_formatter = logging.Formatter('%(levelname)-8s:%(asctime)s:%(lineno)4d - %(message)s')
log_stderrHandler = logging.StreamHandler()
log_stderrHandler.setFormatter(log_formatter)
logger.addHandler(log_stderrHandler)
if LOG_FILENAME:
    #log_fileHandler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=LOG_FILE_MAXSIZE, backupCount=LOG_FILE_BACKUPCOUNT)
    log_fileHandler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='d', interval=LOG_FILE_INTERVAL, backupCount=LOG_FILE_BACKUPCOUNT) 
    log_fileHandler.setFormatter(log_formatter)
    logger.addHandler(log_fileHandler)
logger.propagate = False

os.environ['TZ'] = 'US/Eastern'

default_wiki_page_content='''---
    ## Configuration for /u/subwatchbot -  note this file uses yaml syntax - this wiki page should be unlisted, and set to view/edit by mods only
    ##
    ## This bot requires at least the following moderator permissions:
    ##    posts - to moderate submissions/comments
    ##    access - to be able to ban users
    ##    wiki - to be able to read the bot configuration wiki (THIS)page: /r/<subreddit>/wiki/subwatchbot
    ##    mail (optional) - to be able to mute users in addition to banning them (optional if must_when_banned set to true)
    ##    config (optional) - to be able to append users to the list in the automoderator rule (OR add perms just to config/automoderator page settings)
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- subsearchlist - (REQUIRED) this is the list of subreddits used to calculate the users score and filter users based on their activity in these subreddits
    #
    subsearchlist:
      - TrollSubreddit
      - OtherTrollSubreddit
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- mute_when_banned - (optional) false by default, the bot will also mute the user when they are banned, NOTE: REQUIRES moderator mail premission setting if enabled
    #- level_report - (optional) above this user score level a report will be generated to the modqueue (unless removed submission/comment is removed instead)
    #- level_remove - (optional) above this user score level the submission/comment will be auto-removed
    #- level_ban - (optional) above this user score level the submission/comment will trigger an automatic user ban
    #- level_automoderator - (optional) above this user score level the submission/comment will trigger an append to the automoderator rule
    #- NOTE: the level settings work together, some examples: if a user score is above remove and above ban, 
    #        the submission/comment will be removed AND the user will be banned, if both the level_report and level_remove are triggered
    #        then the post will be removed and reported to modqueue for further review.  If level_remove is 
    #        set higher than level_report, then posts between those ranges will be just reported to the modqueue.
    #- NOTE: An action such as bans can be disabled by setting to a very high number eg 999999.
    #level_report: 200
    #level_remove: 300
    #level_automoderator: 400
    #level_ban: 600
    #
    # - NOTE ABOUT AUTOMODERATOR: this requires an automoderator rule to be added which follows a specific format.  See the help on /ur/subwatchbot for more info.
    #
    #
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- The multipliers settings can be used to put more weight on comments or submissions if desired.  By default they are both=1 and counted equally.  
    #- comment_multiplier - (optional) comment quantity and total comment karma found in the search subs is multiplied by this multiplier and added to the total score
    #- submission_multiplier - (optional) submission quantity and total karma found in search subs is multiplied by this multiplier and added to the total score
    #comment_multiplier: 1
    #submission_multiplier: 1
    #
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- mute_when_banned - (optional) false by default, the bot will also mute the user when they are banned, NOTE: REQUIRES moderator mail premission setting if enabled
    #mute_when_banned: true
    # 
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- mute_when_banned - (optional) false by default, the bot will also mute the user when they are banned, NOTE: REQUIRES moderator mail premission setting if enabled
    #- userexceptions - (optional) if there is a user that has a score about the thresholds but no action should be taken, then add 
    #-                          them to this list and the bot will bypass them
    #userexceptions:
    #   - UserOne
    #   - UserTwo
'''

# =============================================================================
# FUNCTIONS
# =============================================================================
def create_running_file():
    # creates a file that exists while the process is running
    running_file = open(RUNNING_FILE, "w")
    running_file.write(str(os.getpid()))
    running_file.close()


def create_db():
    # create database tables if don't already exist
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        ccur = con.cursor()
        ccur.execute(
            "CREATE TABLE IF NOT EXISTS processed (id TEXT, epoch INTEGER)")
        ccur.execute("CREATE TABLE IF NOT EXISTS trolldata (user TEXT, epoch INTEGER, sub TEXT, comment_karma INTEGER, comment_count INTEGER, sub_karma INTEGER, sub_count INTEGER)")
        con.commit
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()

# first check if we have recent data on the user in db
def get_user_data_sql(Search_User, Search_Sub):
    # update cache db
    comment_karma = -1
    comment_count = -1
    sub_karma = -1
    sub_count = -1
    min_age = (int(round(time.time())) -
               (86400 * int(Settings['Config']['userdata_refresh_days'])))
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT ifnull(comment_karma,0),ifnull(comment_count,0), ifnull(sub_karma,0), ifnull(sub_count,0), epoch FROM trolldata WHERE user=? and sub=?''', (str(
            Search_User), Search_Sub))
        row = qcur.fetchone()
        if row and row[4] > min_age:
            #logger.debug("Found SQL: %s" % row)
            comment_karma = row[0]
            comment_count = row[1]
            sub_karma = row[2]
            sub_count = row[3]
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        logger.error("User=%s Sub=%s" % (Search_User, Search_Sub))
        sys.exit(1)
    finally:
        if con:
            con.close()
    return [comment_karma, comment_count, sub_karma, sub_count]


def get_author_comments(**kwargs):
    data = {}
    try:
        r = requests.get("https://api.pushshift.io/reddit/comment/search/", params=kwargs)
        data = r.json()
    except requests.exceptions.HTTPError as errh:
        logger.error ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        logger.error ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        logger.error ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        logger.error ("OOps: Something Else",err)
    return data['data']


def get_author_submissions(**swargs):
    r = requests.get("https://api.pushshift.io/reddit/submission/search/", params=swargs)
    data = r.json()
    return data['data']


def refresh_user_data(Search_User, Search_Sub):
    total_comment_karma = 0
    total_comment_count = 0
    total_sub_karma = 0
    total_sub_count = 0

    comments = get_author_comments(
        author=Search_User, size=1000, sort='desc', sort_type='created_utc', subreddit=Search_Sub)
    for comment in comments:
        total_comment_karma += comment['score']
        total_comment_count += 1
    time.sleep(1)

    submissions = get_author_submissions(
        author=Search_User, size=1000, sort='desc', sort_type='created_utc', subreddit=Search_Sub)
    for submit in submissions:
        total_sub_karma += submit['score']
        total_sub_count += 1

    # update cache db
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        icur = con.cursor()
        # CREATE TABLE trolldata (user TEXT, epoch INTEGER, sub TEXT, comment_karma INTEGER, comment_count INTEGER, sub_karma INTEGER, sub_count INTEGER);
        icur.execute("UPDATE trolldata SET epoch=?, comment_karma=?, comment_count=?, sub_karma=?, sub_count=? WHERE user=? and sub=?", [
                     int(round(time.time())), total_comment_karma, total_comment_count, total_sub_karma, total_sub_count, str(Search_User), Search_Sub])
        icur.execute("INSERT INTO trolldata VALUES(?, ?, ?, ?, ?, ?, ?)", [str(Search_User), int(round(
            time.time())), Search_Sub, total_comment_karma, total_comment_count, total_sub_karma, total_sub_count])
        con.commit()
    except sqlite3.Error as e:
        logger.error("Error {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()
    return [total_comment_karma, total_comment_count, total_sub_karma, total_sub_count]


def get_user_score(Search_User, Search_Sub, Search_Subs_List):
    User_Score = 0
    #logger.debug("Getting User Score: %s %s" % (Search_User, Search_Subs_List))
    for sreddit in Search_Subs_List:
        trolldata = []
        sqldata = get_user_data_sql(Search_User, sreddit)
        if sqldata and sqldata[0] != -1:
            #logger.debug("Using SQL Data")
            trolldata = sqldata
        elif not sreddit in trolldata:
            trolldata = refresh_user_data(Search_User, sreddit)
        # add comment score
        User_Score += ((trolldata[0] + trolldata[1]) *
                       int(Settings['SubConfig'][Search_Sub]['comment_multiplier']))
        # add submission score
        User_Score += ((trolldata[2] + trolldata[3]) *
                       int(Settings['SubConfig'][Search_Sub]['comment_multiplier']))
    return User_Score


def check_message_processed_sql(messageid):
    logging.debug("Check processed for id=%s" % messageid)
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT id FROM processed WHERE id=?''', (messageid,))
        row = qcur.fetchone()
        if row:
            return True
        else:
            icur = con.cursor()
            insert_time = int(round(time.time()))
            icur.execute("INSERT INTO processed VALUES(?, ?)",
                         [messageid, insert_time])
            con.commit()
            return False
    except sqlite3.Error as e:
        logger.error("SQL Error:" % e)
    finally:
        if con:
            con.close()


def build_multireddit_groups(subreddits):
    """Splits a subreddit list into groups if necessary (due to url length)."""
    multireddits = []
    current_multi = []
    current_len = 0
    for sub in subreddits:
        if current_len > 3300:
            multireddits.append(current_multi)
            current_multi = []
            current_len = 0
        current_multi.append(sub)
        current_len += len(sub) + 1
    multireddits.append(current_multi)
    return multireddits

def create_default_wiki_page(SubName):
    #if SubName.lower() == 'QualitySocialism'.lower():
    #        return
    reddit.subreddit(SubName).wiki.create('subwatchbot', default_wiki_page_content, reason='Inital Settings Page Creation')
    reddit.subreddit(SubName).wiki['subwatchbot'].mod.update(listed=False,permlevel=2)

def get_subreddit_settings(SubName):
    # either use settings from wikipage or defaults from Config
    wikidata = {}

    if SubName not in Settings['SubConfig']:
        Settings['SubConfig'][SubName] = {}
        Settings['SubConfig'][SubName]['userexceptions'] = []

    try:
        wikipage = reddit.subreddit(SubName).wiki[Settings['Config']['wikipage']]
        wikidata = yaml.safe_load(wikipage.content_md)
    except prawcore.exceptions.Forbidden:
        logger.debug("# wiki permission denied for sub: %s", SubName)
    except Exception:
        # send_error_message(requester, subreddit.display_name,
        #    'The wiki page could not be accessed. Please ensure the page '
        #    'http://www.reddit.com/r/{0}/wiki/{1} exists and that {2} '
        #    'has the "wiki" mod permission to be able to access it.'
        #    .format(subreddit.display_name,
        #            cfg_file.get('reddit', 'wiki_page_name'),
        #            username))
        # create a default wiki page and set to be unlisted and mod edit only
        if not SubName.lower() == 'u_subwatchbot':
           logger.error("%-20s - No WikiPage - Creating Default" % SubName)
           create_default_wiki_page(SubName)

    if not wikidata:
            wikidata = {}
            wikidata['empty'] = True

    # use settings from subreddit wiki else use defaults
    settingkeys = ['level_report', 'level_remove', 'level_ban', 'level_automoderator', 'archive_modmail',
                   'mute_when_banned', 'submission_multiplier', 'comment_multiplier', 'userexceptions', 'subsearchlist', 'use_automoderator', 'TotesMessenger']
    for key in settingkeys:
        if key in wikidata:
            Settings['SubConfig'][SubName][key] = wikidata[key]
        elif key not in Settings['SubConfig'][SubName] and key in Settings['Config']:
            Settings['SubConfig'][SubName][key] = Settings['Config'][key]

    # append the subs moderators to user exction list for the sub
    for moderator in reddit.subreddit(SubName).moderator():
        if moderator.name not in  Settings['SubConfig'][SubName]['userexceptions']:  # This is me!
            Settings['SubConfig'][SubName]['userexceptions'] += [moderator.name]

    # create a sub search list for each subreddit
    if 'subsearchlist' in wikidata:
        logger.debug("%s - Using Wiki SearchList: %s" % (SubName, wikidata['subsearchlist']))
        pass
    elif 'subsearchlist' not in Settings['SubConfig'][SubName]:
        Settings['SubConfig'][SubName]['subsearchlist'] = [ 'chapotraphouse', 'chapotraphouse2']
        logger.debug("%s NO DEFAULT SubSearchList" % SubName)

    logger.debug("%s SETTINGS %s" % (SubName, Settings['SubConfig'][SubName]))

def get_mod_permissions(SubName):
    am_moderator = False
    my_permissions = None
    # Get the list of moderators.
    list_of_moderators = reddit.subreddit(SubName).moderator()

    # Iterate over the list of moderators to see if we are in the list
    for moderator in list_of_moderators:
        if moderator == Settings['Reddit']['username']:  # This is me!
            am_moderator = True  # Turns out, I am a moderator, whoohoo
            # Get the permissions I have as a list. e.g. `['wiki']`
            my_permissions = moderator.mod_permissions

    logger.debug("%s PERMS - Mod=%s Perms=%s" % (SubName, am_moderator, my_permissions))

    if "all" in my_permissions:
        #logger.debug("%s Sub Permissions = ALL" % SubName)
        pass
    else:
        if 'mail' not in my_permissions:
            # make sure we overwide without mail perms
            logger.debug("%s Sub Permissions DOES NOT contain MAIL perms. Setting level_report=0" % SubName)
            Settings['SubConfig'][SubName]['mute_when_banned'] = False
        if 'wiki' not in my_permissions:
            logger.debug("%s Sub Permissions DOES NOT contain WIKI perms." % SubName)
        if 'posts' not in my_permissions:
            logger.debug("%s Sub Permissions DOES NOT contain POSTS perms. Setting level_remove=0" % SubName)
            Settings['SubConfig'][SubName]['level_remove'] = 0
        if 'access' not in my_permissions:
            logger.debug("%s Sub Permissions DOES NOT contain ACCCESS perms. Setting level_ban=0" % SubName)
            Settings['SubConfig'][SubName]['level_ban'] = 0

    # TODO: Send a message to the mods about incorrect permissions maybe
    return am_moderator, my_permissions


def accept_mod_invites():
    logger.debug("Run accept mod invites")

    for message in reddit.inbox.unread(limit=20):
        # pprint.pprint(repr(message))
        message.mark_read()

        # Get the variables of the message.
        msg_subject = message.subject.lower()
        msg_subreddit = message.subreddit

        # Only accept PMs. This excludes, say, comment replies.
        if not message.fullname.startswith('t4_'):
            logger.debug('Messaging: Inbox item is not a message. Skipped.')
            continue

        # Reject non-subreddit messages. This includes messages from regular users.
        if msg_subreddit is None:
            logger.debug(
                'Messaging: Message "{}" is not from a subreddit. Skipped.'.format(msg_subject))
            continue

        # This is an auto-generated moderation invitation message.
        if 'invitation to moderate' in msg_subject:
            # Accept the invitation to moderate.
            logger.info("Messaging: New moderation invite from r/{}.".format(msg_subreddit))
            try:
                message.subreddit.mod.accept_invite()  # Accept the invite.
                logger.info("Messaging: Invite accepted.")
            except praw.exceptions.APIException:  # Invite already accepted error.
                logger.error(
                    "Messaging: Moderation invite error. Already accepted?")
                continue
            new_subreddit = message.subreddit.display_name.lower()

            # Reply to the subreddit confirming the invite.
            current_permissions = get_mod_permissions(str(msg_subreddit))
            if not current_permissions[0]:  # We are not a moderator.
                logger.error("I don't have the right mod permissions. Replied to subreddit.")
                reddit.subreddit(str(msg_subreddit)).message("ATTN: Moderator permissions are not set correct for subwatchbot.  Current=%s Required=Access,Posts,Wiki" % current_permissions[1])

def append_to_automoderator(SubName, NewUser, UserScore):
    wikidata = {}
    Settings['SubConfig'][SubName] = {}
    Settings['SubConfig'][SubName]['userexceptions'] = []
    logger.info("# Appending %s to automod list in %s" % (NewUser, SubName))
    try:
        wikipage = reddit.subreddit(SubName).wiki['config/automoderator']
    except prawcore.exceptions.Forbidden:
        logger.error("# automod config permission denied for sub: %s", SubName)
    except Exception:
        logger.error("# MAYBE automod config permission denied for sub: %s", SubName)

    if not wikipage.may_revise:
        logger.error ("ATTN: We do not have perms to change automoderator config.  Aboring.")
        return

    automodconfigdata=wikipage.content_md
    newconfigdata=""
    header_found=0
    read_users=0
    userlist = []

    # Step through the current automoderator config and read in list of users, then output a new sorted list
    for line in automodconfigdata.splitlines():
        if re.search("####\sSUBWATCH\sBOT",line):
            logger.debug("- FOUND #SUBWATCHBOT header line")
            header_found=1
            read_users=1
            newconfigdata += "%s\n" % line
            offset=line.find("#")
        elif read_users == 1:
            if re.search(r'\s-', line):
                x = line.split("-")
                userlist.append(x[1].strip())
            else:
                read_users=0
                if NewUser.lower() not in userlist:
                    userlist.append("%s # UserScore=%s" % (NewUser.lower(), UserScore))
                    logger.info("%-20s: USER %s APPEND to automoderator list" % (SubName, NewUser))
                else:
                    logger.info("%-20s: USER %s APPEND - already in list, skipping" % (SubName, NewUser))
                    return

                userlistsorted=sorted(userlist)
                for outputuser in userlistsorted:
                    for i in range(0, offset):
                        newconfigdata += ' '
                    newconfigdata += '- %s\n' % outputuser
                newconfigdata += "%s\n" % line
                    
        else:
            newconfigdata += "%s\n" % line

    if header_found == 0:
        logger.debug("ERROR: could NOT FIND  ##### SUBWATCHBOT line in automoderatorconfig")
        return

    # DEBUG
    #for newline in newconfigdata.splitlines():
    #    print ("NEW: %s" % newline)

    # Update the automoderator config
    try:
        wikipage.edit(newconfigdata, reason='SUBWATCHBOT added: %s UserScore=%s' % (NewUser.lower(), UserScore))
        logger.info("%-20s: Updated automod config" % SubName)
    except Exception as err:
        logger.warning("Could not edit automod config, skipping")

    return
                

def check_comment(comment):
    authorname = ""
    subname = ""
    searchsubs = []
    subname = str(comment.subreddit).lower()
    authorname = str(comment.author.name)
    User_Score=0

    logger.info("%-20s: process comment: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M', time.localtime(comment.created_utc)), authorname, comment.permalink))

    # user exceptions
    if re.search('bot',str(authorname),re.IGNORECASE):
            logger.info("%-20s:   bot user skip" % subname)
            return
    if authorname.lower() == "automoderator":
            logger.info("%-20s:   automoderator user skip" % subname)
            return
    if 'userexceptions' in Settings['SubConfig'][subname]:
        if authorname.lower() in (name.lower() for name in Settings['SubConfig'][subname]['userexceptions']):
            logger.info("%-20s:   userexceptions, skipping: %s" % (subname,authorname))
            return

    if 'subsearchlist' not in Settings['SubConfig'][subname]:
        logger.error("UNKNOWN subsearchlist for (%s) REFRESHING." % subname)
        logger.error("Before SUB: %s" % Settings['SubConfig'][subname]['subsearchlist'])
        get_subreddit_settings(subname)

    # get user score
    if 'subsearchlist' in Settings['SubConfig'][subname]:
        searchsubs = Settings['SubConfig'][subname]['subsearchlist']
        User_Score = get_user_score(authorname, subname, searchsubs)
        logger.info("%-20s:   user %s score=%s" % (subname, authorname, User_Score))
    else:
        logger.error("UNKNOWN subsearchlist for (%s)" % subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])
        return
    
    # Processing based on User_Score
    # 
    if int(User_Score) > int(Settings['SubConfig'][subname]['level_remove']) and int(Settings['SubConfig'][subname]['level_remove']) > 0:
        if comment.banned_by is not None:
            logger.info("%-20s:    -Removed-ALREADY removed by %s" % (subname,comment.banned_by))
        else:
            logger.info("%-20s:    +Removed" % subname)
            comment.mod.remove()

    if int(User_Score) > int(Settings['SubConfig'][subname]['level_automoderator']) and int(Settings['SubConfig'][subname]['level_automoderator']) > 0:
       logger.info("%-20s:    +RUN automod append" % subname)
       append_to_automoderator(subname, authorname, User_Score)
    
    if "level_ban" not in Settings['SubConfig'][subname]:
        logger.error("C-level_ban not found for sub: (%s)" % subname)
        get_subreddit_settings(subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])

    if int(User_Score) > int(Settings['SubConfig'][subname]['level_ban']) and int(Settings['SubConfig'][subname]['level_ban']) > 0:
        # ban
        if comment.author not in reddit.subreddit(subname).banned():
            logger.info("%-20s:    +BAN User %s %s>%s" % (subname, comment.author, User_Score, Settings['SubConfig'][subname]['level_ban']))
            reddit.subreddit(subname).banned.add(comment.author, ban_reason='TrollDetected Score='+str(User_Score), note='https://reddit.com'+comment.permalink)
        else:
            logger.info("%-20s:    -BAN User %s ALREADY BANNED" % (subname, comment.author))
        # mute
        if Settings['SubConfig'][subname]['mute_when_banned']:
            if comment.author not in reddit.subreddit(subname).muted():
                logger.info("%-20s:    +MUTE User %s" % (subname, comment.author.id))
                reddit.subreddit(subname).muted.add(comment.author)
            else:
                logger.info("%-20s:    -MUTE User %s ALREADY MUTED" % (subname,comment.author))

    # elif because user was banned, then no need to report to modqueue for further review
    elif int(User_Score) > int(Settings['SubConfig'][subname]['level_report']) and int(Settings['SubConfig'][subname]['level_report']) > 0:
        logger.info("%-20s:    +Report to ModQueue" % subname)
        comment.report('Possible Troll Post -- User Score=%s' % User_Score)


def check_submission(submission):
    authorname = ""
    subname = ""
    searchsubs = []
    subreddit = submission.subreddit
    subname = str(submission.subreddit.display_name).lower()
    authorname = str(submission.author)
    User_Score=0

    # user exceptions
    if re.search('bot',str(authorname),re.IGNORECASE):
            logger.debug("    bot user skip")
            return
    if authorname.lower() == "automoderator":
            logger.debug("    bot user skip")
            return
    if 'userexceptions' in Settings['SubConfig'][subname]:
        if authorname.lower() in (name.lower() for name in Settings['SubConfig'][subname]['userexceptions']):
            logger.debug("    userexceptions, skipping: %s" % authorname)
            return

    logger.info("%-20s: process submission: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(submission.created_utc)), submission.author, submission.permalink))

    # get user score
    if 'subsearchlist' not in Settings['SubConfig'][subname]:
        get_subreddit_settings(subname)

    if 'subsearchlist' in Settings['SubConfig'][subname]:
        searchsubs = Settings['SubConfig'][subname]['subsearchlist']
        User_Score = get_user_score(authorname, subname, searchsubs)
        logger.info("%-20s:   user %s score=%s" % (subname, authorname, User_Score))
    else:
        logger.error("UNKNOWN subsearchlist for (%s)" % subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])
        logger.error("ALL config: %s" % Settings['SubConfig'])
        return

    
    # Processing based on User_Score
    # 
    if int(User_Score) > int(Settings['SubConfig'][subname]['level_remove']) and int(Settings['SubConfig'][subname]['level_remove']) > 0:
        if submission.selftext == "[Removed]":
            logger.info("%-20s:    -Remove-ALREADY by %s" % (subname, submission.selftext))
        elif submission.selftext == "[deleted]":
            logger.info("%-20s:    -Remove-ALREADY by User Deleted %s" % (subname, submission.selftext))
        else:
            logger.info("%-20s:    +Remove" % subname)
            submission.mod.remove()
            logger.info("%-20s:    +Lock" % subname)
            submission.mod.lock()

    if 'level_automoderator' not in Settings['SubConfig'][subname]:
        get_subreddit_settings(subname)

    if 'level_automoderator' not in Settings['SubConfig'][subname]:
        logger.error("level_automoderator not found for sub: (%s)" % subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])
        logger.error("ALL config: %s" % Settings['SubConfig'])
        return

    if int(User_Score) > int(Settings['SubConfig'][subname]['level_automoderator']) and int(Settings['SubConfig'][subname]['level_automoderator']) > 0:
        logger.info("%-20s:    +RUN automod append" % subname)
        append_to_automoderator(subname, authorname, User_Score)

    if 'level_ban' not in Settings['SubConfig'][subname]:
        logger.error("S-level_ban not found for sub: (%s)" % subname)
        get_subreddit_settings(subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])
        logger.error("ALL config: %s" % Settings['SubConfig'])

    if int(User_Score) > int(Settings['SubConfig'][subname]['level_ban']) and int(Settings['SubConfig'][subname]['level_ban']) > 0:
        # ban
        if submission.author not in reddit.subreddit(subname).banned():
            logger.info("%-20s:    +BAN User %s" % (subname, submission.author))
            reddit.subreddit(subname).banned.add(submission.author, ban_reason='TrollDetected Score='+str(User_Score), note='https://reddit.com'+submission.permalink)
        else:
            logger.info("%-20s:    -BAN User %s ALREADY BANNED" % (subname, submission.author))
        # mute
        if Settings['SubConfig'][subname]['mute_when_banned']:
            if submission.author not in reddit.subreddit(subname).muted():
                logger.info("%-20s:    +MUTE User %s" % (subname, submission.author))
                reddit.subreddit(subname).muted.add(submission.author)
            else:
                logger.info("%-20s:    -MUTE User %s ALREADY MUTED" % (subname, submission.author))

    # elif because user was banned, then no need to report to modqueue for further review
    elif int(User_Score) > int(Settings['SubConfig'][subname]['level_report']) and int(Settings['SubConfig'][subname]['level_report']) > 0:
        logger.info("%-20s:    +Report to ModQueue" % subname)
        submission.report('Possible Troll Post -- User Score=%s' % User_Score)


# =============================================================================
# MAIN
# =============================================================================


def main():
    start_process = False
    logger.info("start program")

    # create db tables if needed
    logger.debug("Create DB tables if needed")
    create_db()

    if ENVIRONMENT == "DEV" and os.path.isfile(RUNNING_FILE):
        os.remove(RUNNING_FILE)
        logger.debug("DEV=running file removed")

    if not os.path.isfile(RUNNING_FILE):
        create_running_file()
        start_process = True
    else:
        logger.error("bot already running! Will not start.")

    # Initalize
    next_refresh_time = 0
    subList = []

    while start_process and os.path.isfile(RUNNING_FILE):
        #logger.debug("Start Main Loop")

        # Only refresh sublists and wiki settings once an hour
        if int(round(time.time())) > next_refresh_time:
            logger.debug("REFRESH Start")
            accept_mod_invites()
            for subs in reddit.user.moderator_subreddits():
                sub_permissions = []
                SubName = str(subs).lower()
                get_subreddit_settings(SubName)
                sub_permissions = get_mod_permissions(SubName)
                if sub_permissions[0]:  # We are a moderator.
                    if 'subsearchlist' in Settings['SubConfig'][SubName]:
                        if SubName not in subList:
                            subList.append(SubName)
                else: 
                    logger.warning("SKIPPING SUB %s due to no moderator permissions", SubName)
            logger.info("subList: %s" % subList)
            next_refresh_time = int(
                round(time.time())) + (60 * int(Settings['Config']['config_refresh_mins']))
            logger.info("--- Settings REFRESH Completed")
            #logger.info("%s" % Settings['SubConfig'])

        multireddits = build_multireddit_groups(subList)
        for multi in multireddits:
            #subreddit = reddit.subreddit(settings.REDDIT_SUBREDDIT)
            subreddit = reddit.subreddit('+'.join(multi))
            comment_stream = subreddit.stream.comments(pause_after=-1)
            submission_stream = subreddit.stream.submissions(pause_after=-1)

            try:
              # process submission stream
              for submission in submission_stream:
                if submission is None:
                   break
                elif check_message_processed_sql(submission.id):
                   continue
                else:
                   check_submission(submission)

              # process comment stream
              for comment in comment_stream:
                if comment is None:
                   break
                elif check_message_processed_sql(comment.id):
                   continue
                else:
                   check_comment(comment)

            # Allows the bot to exit on ^C, all other exceptions are ignored
            except KeyboardInterrupt:
                break
            except Exception as err:
                logger.exception("Unknown Exception in Main Loop")

        #logger.debug("End Main Loop - Pause %s secs" % Settings['Config']['main_loop_pause_secs'])
        time.sleep(int(Settings['Config']['main_loop_pause_secs']))

    logger.info("end program")
    sys.exit()


# =============================================================================
# RUNNER
# =============================================================================

if __name__ == '__main__':
    # Reddit info
    reddit = praw.Reddit(client_id=Settings['Reddit']['client_id'],
                         client_secret=Settings['Reddit']['client_secret'],
                         password=Settings['Reddit']['password'],
                         user_agent=Settings['Reddit']['user_agent'],
                         username=Settings['Reddit']['username'])
    main()
