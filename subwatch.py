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
pp = pprint.PrettyPrinter(indent=4)
import json
sys.path.append("%s/github/bots/userdata" % os.getenv("HOME"))
from RedditUserData import get_User_Data



# =============================================================================
# GLOBALS
# =============================================================================
# Reads the config file
config = configparser.ConfigParser()
config.read("bot.cfg")
config.read("auth.cfg")

Settings = {}
Settings = {s: dict(config.items(s)) for s in config.sections()}
Settings['SubConfig'] = {}


ENVIRONMENT = config.get("BOT", "environment")
DEV_USER_NAME = config.get("BOT", "dev_user")
RUNNING_FILE = "bot.pid"


database = "%s/github/bots/subwatchbot/usersdata.db" % os.getenv("HOME")



LOG_LEVEL = logging.INFO
#LOG_LEVEL = logging.DEBUG
LOG_FILENAME = Settings['Config']['logfile']
LOG_FILE_INTERVAL = 2
LOG_FILE_BACKUPCOUNT = 5
LOG_FILE_MAXSIZE = 5000 * 256

# Define custom log level 5=trace
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, 'TRACE')
def trace(self, message, *args, **kws):
        self.log(TRACE_LEVEL, message, *args, **kws) 
logging.Logger.trace = trace

logger = logging.getLogger('bot')
logger.setLevel(LOG_LEVEL)
log_formatter = logging.Formatter('%(levelname)-8s:%(asctime)s:%(lineno)4d - %(message)s')
log_stderrHandler = logging.StreamHandler()
log_stderrHandler.setFormatter(log_formatter)
logger.addHandler(log_stderrHandler)
if LOG_FILENAME:
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
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
    #- misinfo_approve - (optional) false by default, the bot will automatically approve misinformation reports.
    #misinfo_approve: true
    # 
    #------------------------------------------------------------------------------------------------------------------------------------------------------#
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
        ccur.execute("CREATE TABLE IF NOT EXISTS processed (id TEXT, epoch INTEGER)")
        con.commit
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()

def get_user_score(Search_User, Search_Sub, Search_Subs_List):
    User_Score = 0
    User_Data = get_User_Data(reddit, Search_User, Search_Subs_List, 7, 'reddit', 'SMALL', database)
    for sreddit in Search_Subs_List:
        # add comment score
        User_Score += ((User_Data[sreddit]['c_karma'] + User_Data[sreddit]['c_count']) *
                       int(Settings['SubConfig'][Search_Sub]['comment_multiplier']))
        # add submission score
        User_Score += ((User_Data[sreddit]['s_karma'] + User_Data[sreddit]['s_count']) *
                       int(Settings['SubConfig'][Search_Sub]['comment_multiplier']))
    return User_Score

def get_user_subkarma(Search_User, Search_Sub):
    Sub_Karma = 0
    Sub_Data = get_User_Data(reddit, Search_User, [ Search_Sub ])

    # add comment score
    Sub_Karma += Sub_Data[Search_Sub]['c_karma'] + Sub_Data[Search_Sub]['c_count']
    # add submission score
    Sub_Karma += Sub_Data[Search_Sub]['s_karma'] + Sub_Data[Search_Sub]['s_count']

    return Sub_Karma


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
                   'mute_when_banned', 'submission_multiplier', 'comment_multiplier', 'userexceptions', 'subsearchlist', 'use_automoderator', 'TotesMessenger', 'min_post_karma', 'misinfo_approve']
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

    logger.trace("%s SETTINGS %s" % (SubName, Settings['SubConfig'][SubName]))

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

    logger.trace("%s PERMS - Mod=%s Perms=%s" % (SubName, am_moderator, my_permissions))

    if "all" in my_permissions:
        pass
    else:
        if 'mail' not in my_permissions:
            # make sure we overwide without mail perms
            logger.trace("%s Sub Permissions DOES NOT contain MAIL perms. Setting level_report=0" % SubName)
            Settings['SubConfig'][SubName]['mute_when_banned'] = False
        if 'wiki' not in my_permissions:
            logger.trace("%s Sub Permissions DOES NOT contain WIKI perms." % SubName)
        if 'posts' not in my_permissions:
            logger.trace("%s Sub Permissions DOES NOT contain POSTS perms. Setting level_remove=0" % SubName)
            Settings['SubConfig'][SubName]['level_remove'] = 0
        if 'access' not in my_permissions:
            logger.trace("%s Sub Permissions DOES NOT contain ACCCESS perms. Setting level_ban=0" % SubName)
            Settings['SubConfig'][SubName]['level_ban'] = 0

    # TODO: Send a message to the mods about incorrect permissions maybe
    return am_moderator, my_permissions


def accept_mod_invites():
    logger.trace("Run accept mod invites")

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
    userlist = {}

    # Step through the current automoderator config and read in list of users, then output a new sorted list
    for line in automodconfigdata.splitlines():
        if re.search("####\sSUBWATCH\sBOT",line):
            logger.trace("- FOUND #SUBWATCHBOT header line")
            header_found=1
            read_users=1
            newconfigdata += "%s\n" % line
            offset=line.find("#")
        elif read_users == 1:
            if re.search(r'\s-', line):
                x = line.split("-")
                xname = x[1].split()
                x_username = xname[0]
                if len(xname) > 1:
                    x_userscore = xname[2]
                else:
                    x_userscore = ""
                userlist[x_username] = x_userscore
            else:
                logger.info("processing end line")
                read_users=0
                if NewUser.lower() not in userlist:
                    userlist[NewUser.lower()] = "UserScore=%s" % UserScore
                    logger.info("%-20s: USER %s APPEND to automoderator list" % (SubName, NewUser))
                else:
                    logger.info("%-20s: USER %s APPEND SKIP - already in list, skipping" % (SubName, NewUser))
                    return

                for outputuser in sorted (userlist.keys()):
                    for i in range(0, offset):
                        newconfigdata += ' '
                    newconfigdata += '- %s # %s\n' % (outputuser, userlist[outputuser])
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
            comment.mod.lock()
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
            logger.trace("    bot user skip")
            return
    if authorname.lower() == "automoderator":
            logger.trace("    bot user skip")
            return
    if 'userexceptions' in Settings['SubConfig'][subname]:
        if authorname.lower() in (name.lower() for name in Settings['SubConfig'][subname]['userexceptions']):
            logger.debug("    userexceptions, skipping: %s" % authorname)
            return

    logger.info("%-20s: process submission: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(submission.created_utc)), submission.author, submission.permalink))

    if 'subsearchlist' not in Settings['SubConfig'][subname]:
        get_subreddit_settings(subname)

    # Skip if already approved
    #
    approved_by = str(submission.approved_by)
    if approved_by and approved_by != "None":
        logger.info(" --- Approved by(skipping): (%s)" % approved_by)
        return

    # Processing based on User_Score
    # 
    User_Sub_Karma = get_user_subkarma(authorname, subname)
    if 'min_post_karma' in Settings['SubConfig'][subname] and int(Settings['SubConfig'][subname]['min_post_karma']) > 0:
        if int(User_Sub_Karma) > int(Settings['SubConfig'][subname]['min_post_karma']):
            logger.info("%-20s:   user %s subkarma=%s -- POST APPROVED %s" % (subname, authorname, User_Sub_Karma, Settings['SubConfig'][subname]['min_post_karma']))
        else:
            logger.info("%-20s:   user %s subkarma=%s -- POST *DENY* %s" % (subname, authorname, User_Sub_Karma, Settings['SubConfig'][subname]['min_post_karma']))

            replynote = "!ReviewPost - submission made by new user please review /u/%s (%s)" % ( authorname, User_Sub_Karma )

            modnote = "**Attention: A submission was made by a user with low karama in the subreddit and automatically removed.  Please check for quality before approving.**\n\n"
            modnote += "User: /u/%s  subkarma=%s  (less than %s)\n\n" % (authorname, User_Sub_Karma, Settings['SubConfig'][subname]['min_post_karma'])
            modnote += "Link: http://reddit.com%s\n\n" % submission.permalink
            modnote += "Title:\n\n"
            modnote += ">%s\n\n" % submission.title
            modnote += "\n\n"
    
            if 'goldandblack' in subname:
               submission.reply(replynote)
            else:
               submission.mod.remove()
               reddit.subreddit(subname).message("Low Karma Submission", modnote)

    # Processing based on User_Score
    # 
    if 'subsearchlist' in Settings['SubConfig'][subname]:
        searchsubs = Settings['SubConfig'][subname]['subsearchlist']
        User_Score = get_user_score(authorname, subname, searchsubs)
        logger.info("%-20s:   user %s score=%s" % (subname, authorname, User_Score))
    else:
        logger.error("UNKNOWN subsearchlist for (%s)" % subname)
        logger.error("Sub config: %s" % Settings['SubConfig'][subname])
        logger.error("ALL config: %s" % Settings['SubConfig'])
        return
    
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

def check_modqueuereport(reportitem):
    authorname = ""
    subname = ""
    subreddit = reportitem.subreddit
    subname = str(reportitem.subreddit.display_name).lower()
    ReportMisinfoFound = False
    ReportOtherFound = False

    if not Settings['SubConfig'][subname]['misinfo_approve']:
       return

    if reportitem.name.startswith("t1"):
        reportType = "Comment"
    elif reportitem.name.startswith("t3"):
        reportType = "Submission"
    else:
        return

    for user_report in reportitem.user_reports:
        if "This is misinformation" in user_report[0]:
            ReportMisinfoFound = True
        else:
            ReportOtherFound = True

        if ReportMisinfoFound and not ReportOtherFound:
            logger.info("%-20s: process MODQUEUE misinfo item: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(reportitem.created_utc)), str(reportitem.author), str(reportitem.permalink)))
            reportitem.mod.ignore_reports()
            reportitem.mod.approve()

# =============================================================================
# MAIN
# =============================================================================


def main():
    start_process = False
    logger.info("start program")

    # create db tables if needed
    logger.trace("Create DB tables if needed")
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
    subList_prev = []

    while start_process and os.path.isfile(RUNNING_FILE):
        logger.debug("Start Main Loop")

        # Only refresh sublists and wiki settings once an hour
        if int(round(time.time())) > next_refresh_time:
            logger.debug("REFRESH Start")
            accept_mod_invites()
            #redditorme = reddit.user.me()
            for subs in reddit.user.me().moderated():
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

        #subList = [ 'subwatchbot_test', 'minarchism' ]
        if not subList == subList_prev:
           logger.debug("Build(re) multireddit")
           multireddits = build_multireddit_groups(subList)
           for multi in multireddits:
            #subreddit = reddit.subreddit(settings.REDDIT_SUBREDDIT)
             subreddit = reddit.subreddit('+'.join(multi))
           subList_prev = subList

        subreddit = reddit.subreddit('+'.join(multi))
        comment_stream = subreddit.stream.comments(pause_after=-1)
        submission_stream = subreddit.stream.submissions(pause_after=-1)
        modqueue_stream = subreddit.mod.stream.reports(pause_after=-1)

        try:
          # process submission stream
          logger.debug("MAIN-Check submissions")
          for submission in submission_stream:
            if submission is None:
               break
            elif check_message_processed_sql(submission.id):
               continue
            else:
               check_submission(submission)

          # process comment stream
          logger.debug("MAIN-Check comments")
          for comment in comment_stream:
            if comment is None:
               break
            elif check_message_processed_sql(comment.id):
               continue
            else:
               check_comment(comment)

          # process modqueue stream
          logger.debug("MAIN-Check modqueue")
          for reportitem in modqueue_stream:
            if reportitem is None:
              break
            else:
              check_modqueuereport(reportitem)


        # Allows the bot to exit on ^C, all other exceptions are ignored
        except KeyboardInterrupt:
            break
        except Exception as err:
            logger.exception("Unknown Exception in Main Loop")

        logger.debug("End Main Loop - Pause %s secs" % Settings['Config']['main_loop_pause_secs'])
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
