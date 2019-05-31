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
#from datetime import datetime
#from dateutil import relativedelta
import random
import yaml
import re
import requests
#import datetime
import sqlite3
import pprint
#import settings


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

#LOG_LEVEL = logging.INFO
LOG_LEVEL = logging.DEBUG
LOG_FILENAME = Settings['Config']['logfile']
LOG_FILE_BACKUPCOUNT = 5
LOG_FILE_MAXSIZE = 1024 * 256

logger = logging.getLogger('bot')
logger.setLevel(LOG_LEVEL)
log_formatter = logging.Formatter(
    '%(levelname)-8s:%(name)s-%(funcName)s-%(lineno)d-%(asctime)s - %(message)s')
log_stderrHandler = logging.StreamHandler()
log_stderrHandler.setFormatter(log_formatter)
logger.addHandler(log_stderrHandler)
if LOG_FILENAME:
    log_fileHandler = logging.handlers.RotatingFileHandler(
        LOG_FILENAME, maxBytes=LOG_FILE_MAXSIZE, backupCount=LOG_FILE_BACKUPCOUNT)
    log_fileHandler.setFormatter(log_formatter)
    logger.addHandler(log_fileHandler)
logger.propagate = False

os.environ['TZ'] = 'US/Eastern'


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


# TODO: Implement user exception list support
#    if re.search('bot',str(author),re.IGNORECASE):
#        userFlag="Bypass_Bot"

# TODO: work on submission request processing
"""
def check_submission(submission):
    logger.info("submission: %s %s  user=%-20s http://reddit.com%s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                                                                     time.localtime(submission.created_utc)), submission.id, submission.author, submission.permalink))
    User_Score = get_user_score(
        submission.author, settings.REDDIT_SUBREDDIT, settings.CHECK_KARMA_SUBS)
    logger.debug("    user scores: local=%s remote=%s flag=%s" %
                 (userData[1], userData[2], userData[0]))

    if userData[0].lower() == "REMOTE_VERY".lower():  # Auto Ban and Remove Submission
        logger.info("    user scores: local=%s remote=%s flag=%s" %
                    (userData[1], userData[2], userData[0]))

        if submission.selftext == "[Removed]":
            logger.info("    -Remove-ALREADY-Removed %s" % submission.selftext)
        elif submission.selftext == "[deleted]":
            logger.info("    -Remove-ALREADY")
            logger.info("    -User Deleted %s" % submission.selftext)
        else:
            logger.info("    +Remove")
            submission.mod.remove()
            logger.info("    +Lock")
            submission.mod.lock()

        r = praw.Reddit(user_agent=settings.REDDIT_USER_AGENT, client_id=settings.REDDIT_CLIENT_ID,
                        client_secret=settings.REDDIT_CLIENT_SECRET, username=settings.REDDIT_USERNAME, password=settings.REDDIT_PASSWORD)
        if submission.author not in r.subreddit(settings.REDDIT_SUBREDDIT).banned():
            logger.info("    +BAN User")
            r.subreddit(settings.REDDIT_SUBREDDIT).banned.add(
                submission.author, ban_reason='TrollDetected Score='+str(userData[2]), note='https://reddit.com'+submission.permalink)
        else:
            logger.info("    -BAN User-ALREADY")

        if submission.author not in r.subreddit(settings.REDDIT_SUBREDDIT).muted():
            logger.info("    +MUTE User")
            r.subreddit(settings.REDDIT_SUBREDDIT).muted.add(submission.author)
        else:
            logger.info("    -MUTE User-ALREADY")

    elif userData[0].lower() == "REMOTE_BAD".lower():  # Report Submission to modqueue
        logger.info("    user scores: local=%s remote=%s flag=%s" %
                    (userData[1], userData[2], userData[0]))
        logger.info("    +Report to ModQueue")
        submission.report(
            'Possible Troll Post -- User Bad Karma Score=%s' % userData[2])

    # elif userData[0] == "Local_Good":
    # elif userData[0] == "Local_New":
    # elif userData[0] == "Local_Low":
"""

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
            logger.debug("Found SQL: %s" % row)
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
    r = requests.get(
        "https://api.pushshift.io/reddit/comment/search/", params=kwargs)
    data = r.json()
    return data['data']


def get_author_submissions(**swargs):
    r = requests.get(
        "https://api.pushshift.io/reddit/submission/search/", params=swargs)
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


def get_subreddit_settings(SubName):
    # either use settings from wikipage or defaults from Config
    wikidata = {}
    Settings['SubConfig'][SubName] = {}
    try:
        wikipage = reddit.subreddit(
            SubName).wiki[Settings['Config']['wikipage']]
        wikidata = yaml.safe_load(wikipage.content_md)
    except Exception:
        # send_error_message(requester, subreddit.display_name,
        #    'The wiki page could not be accessed. Please ensure the page '
        #    'http://www.reddit.com/r/{0}/wiki/{1} exists and that {2} '
        #    'has the "wiki" mod permission to be able to access it.'
        #    .format(subreddit.display_name,
        #            cfg_file.get('reddit', 'wiki_page_name'),
        #            username))
        logger.info("%s - No WikiPage" % SubName)

    # use settings from subreddit wiki else use defaults
    settingkeys = ['level_warn', 'level_remove', 'level_ban', 'archive_modmail',
                   'mute_when_banned', 'submission_multiplier', 'comment_multiplier']
    for key in settingkeys:
        if key in wikidata:
            Settings['SubConfig'][SubName][key] = wikidata[key]
        elif key in Settings['Config']:
            Settings['SubConfig'][SubName][key] = Settings['Config'][key]
        else:
            logger.error("Uknown key: %s" % key)

    # create a sub search list for each subreddit
    if 'subsearchlist' in wikidata:
        #logger.debug("%s - Using Wiki SearchList: %s" % (SubName, wikidata['subsearchlist']))
        Settings['SubConfig'][SubName]['subsearchlist'] = wikidata['subsearchlist']
    elif SubName in Settings['SubSearchLists']:
        #logger.debug("%s - Using config-sub SearchList: %s" % (SubName, Settings['SubSearchLists'][SubName]))
        Settings['SubConfig'][SubName]['subsearchlist'] = [
            x.strip() for x in Settings['SubSearchLists'][SubName].split(',')]
    elif 'default' in Settings['SubSearchLists']:
        #logger.debug("%s - Using config-default SearchList: %s" % (SubName, Settings['SubSearchLists']['default']))
        Settings['SubConfig'][SubName]['subsearchlist'] = [
            x.strip() for x in Settings['SubSearchLists']['default'].split(',')]
    else:
        Settings['SubConfig'][SubName]['subsearchlist'] = [
            'chapotraphouse', 'chapotraphouse2']
        logger.error("NO DEFAULT SubSearchList")


def obtain_mod_permissions(subreddit_name):
    """
    A function to check if we have mod permissions in a subreddit, and what kind of mod permissions it has.
    The important ones needed are: wiki - (optional) so that it can get configuration settings from the sub
                                   posts - (optional)
    Giving extra permissions does not matter as it will not use them.
    More info: https://www.reddit.com/r/modhelp/wiki/mod_permissions
    :param subreddit_name: Name of a subreddit.
    :return: A tuple. First item is True/False on whether Artemis is a moderator. Second item is permissions, if any.
    """

    # TODO: check what perms are granted and set some config flags as well as more messages
    am_moderator = False
    my_permissions = None
    # Get the list of moderators.
    list_of_moderators = reddit.subreddit(subreddit_name).moderator()

    # Iterate over the list of moderators to see if Artemis is in it.
    for moderator in list_of_moderators:
        if moderator == Settings['Reddit']['username']:  # This is me!
            am_moderator = True  # Turns out, I am a moderator.
            # Get the permissions I have as a list. e.g. `['wiki']`
            my_permissions = moderator.mod_permissions

    mod_log = 'Mod Permissions: Artemis r/{} moderator status is {}. Permissions are {}.'
    logger.debug("%s Mod=%s Perms=%s" %
                 (subreddit_name, am_moderator, my_permissions))
    return am_moderator, my_permissions


def accept_mod_invites():
    logger.info("Run accept mod invites")

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
            logger.info(
                "Messaging: New moderation invite from r/{}.".format(msg_subreddit))
            try:
                message.subreddit.mod.accept_invite()  # Accept the invite.
                logger.info("Messaging: Invite accepted.")
            except praw.exceptions.APIException:  # Invite already accepted error.
                logger.error(
                    "Messaging: Moderation invite error. Already accepted?")
                continue
            new_subreddit = message.subreddit.display_name.lower()

            # Reply to the subreddit confirming the invite.
            current_permissions = obtain_mod_permissions(str(msg_subreddit))
            if current_permissions[0]:  # We are a moderator.
                # Fetch the list of moderator permissions we have. This will be an empty list if we are a mod
                # but has no actual permissions.
                list_of_permissions = current_permissions[1]
                if 'wiki' not in list_of_permissions:
                    # We were invited to be a mod but don't have the proper permissions. Let the mods know.
                    #message.reply(MSG_ACCEPT_WRONG_PERMISSIONS + BOT_DISCLAIMER.format(msg_subreddit))
                    logger.info(
                        "Messaging: I don't have the right wiki permissions. Replied to subreddit.")
            else:
                return  # Exit as we are not a moderator.


#---- process functions ----#
def check_comment(comment):
    authorname = ""
    subname = ""
    searchsubs = []
    subname = str(comment.subreddit).lower()


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


def get_subreddit_settings(SubName):
    # either use settings from wikipage or defaults from Config
    wikidata = {}
    Settings['SubConfig'][SubName] = {}
    try:
        wikipage = reddit.subreddit(
            SubName).wiki[Settings['Config']['wikipage']]
        wikidata = yaml.safe_load(wikipage.content_md)
    except Exception:
        # send_error_message(requester, subreddit.display_name,
        #    'The wiki page could not be accessed. Please ensure the page '
        #    'http://www.reddit.com/r/{0}/wiki/{1} exists and that {2} '
        #    'has the "wiki" mod permission to be able to access it.'
        #    .format(subreddit.display_name,
        #            cfg_file.get('reddit', 'wiki_page_name'),
        #            username))
        logger.info("%s - No WikiPage" % SubName)
        # TODO: create a default wiki page and set to be unlisted and mod edit only

    # use settings from subreddit wiki else use defaults
    settingkeys = ['level_warn', 'level_remove', 'level_ban', 'archive_modmail',
                   'mute_when_banned', 'submission_multiplier', 'comment_multiplier', 'userexceptions', 'subsearchlist']
    for key in settingkeys:
        if key in wikidata:
            Settings['SubConfig'][SubName][key] = wikidata[key]
        elif key in Settings['Config']:
            Settings['SubConfig'][SubName][key] = Settings['Config'][key]
        elif key not in settingkeys:
            logger.error("Uknown key: %s" % key)

    # create a sub search list for each subreddit
    if 'subsearchlist' in wikidata:
        #logger.debug("%s - Using Wiki SearchList: %s" % (SubName, wikidata['subsearchlist']))
        #Settings['SubConfig'][SubName]['subsearchlist'] = wikidata['subsearchlist']
        pass
    elif SubName in Settings['SubSearchLists']:
        #logger.debug("%s - Using config-sub SearchList: %s" % (SubName, Settings['SubSearchLists'][SubName]))
        Settings['SubConfig'][SubName]['subsearchlist'] = [ x.strip() for x in Settings['SubSearchLists'][SubName].split(',')]
    elif 'default' in Settings['SubSearchLists']:
        #logger.debug("%s - Using config-default SearchList: %s" % (SubName, Settings['SubSearchLists']['default']))
        Settings['SubConfig'][SubName]['subsearchlist'] = [ x.strip() for x in Settings['SubSearchLists']['default'].split(',')]
    else:
        Settings['SubConfig'][SubName]['subsearchlist'] = [ 'chapotraphouse', 'chapotraphouse2']
        logger.error("NO DEFAULT SubSearchList")


def obtain_mod_permissions(subreddit_name):
    """
    A function to check if we have mod permissions in a subreddit, and what kind of mod permissions it has.
    The important ones needed are: wiki - (optional) so that it can get configuration settings from the sub
                                   posts - (optional)
    Giving extra permissions does not matter as it will not use them.
    More info: https://www.reddit.com/r/modhelp/wiki/mod_permissions
    :param subreddit_name: Name of a subreddit.
    :return: A tuple. First item is True/False on whether Artemis is a moderator. Second item is permissions, if any.
    """

    am_moderator = False
    my_permissions = None
    # Get the list of moderators.
    list_of_moderators = reddit.subreddit(subreddit_name).moderator()

    # Iterate over the list of moderators to see if Artemis is in it.
    for moderator in list_of_moderators:
        if moderator == Settings['Reddit']['username']:  # This is me!
            am_moderator = True  # Turns out, I am a moderator.
            # Get the permissions I have as a list. e.g. `['wiki']`
            my_permissions = moderator.mod_permissions

    mod_log = 'Mod Permissions: Artemis r/{} moderator status is {}. Permissions are {}.'
    logger.debug("%s Mod=%s Perms=%s" %
                 (subreddit_name, am_moderator, my_permissions))
    return am_moderator, my_permissions


def accept_mod_invites():
    logger.info("Run accept mod invites")

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
            logger.info(
                "Messaging: New moderation invite from r/{}.".format(msg_subreddit))
            try:
                message.subreddit.mod.accept_invite()  # Accept the invite.
                logger.info("Messaging: Invite accepted.")
            except praw.exceptions.APIException:  # Invite already accepted error.
                logger.error(
                    "Messaging: Moderation invite error. Already accepted?")
                continue
            new_subreddit = message.subreddit.display_name.lower()

            # Reply to the subreddit confirming the invite.
            current_permissions = obtain_mod_permissions(str(msg_subreddit))
            if current_permissions[0]:  # We are a moderator.
                # Fetch the list of moderator permissions we have. This will be an empty list if we are a mod
                # but has no actual permissions.
                list_of_permissions = current_permissions[1]
                if 'wiki' not in list_of_permissions:
                    # We were invited to be a mod but don't have the proper permissions. Let the mods know.
                    #message.reply(MSG_ACCEPT_WRONG_PERMISSIONS + BOT_DISCLAIMER.format(msg_subreddit))
                    logger.info(
                        "Messaging: I don't have the right wiki permissions. Replied to subreddit.")
            else:
                return  # Exit as we are not a moderator.


def check_comment(comment):
    authorname = ""
    subname = ""
    searchsubs = []
    subname = str(comment.subreddit).lower()
    authorname = str(comment.author)
    logger.debug("process comment: %s %s user=%s http://reddit.com%s" % (subname, time.strftime(
        '%Y-%m-%d %H:%M', time.localtime(comment.created_utc)), authorname, comment.permalink))
    searchsubs = [x.strip()
                  for x in Settings['SubSearchLists'][subname].split(',')]
    User_Score = get_user_score(authorname, subname, searchsubs)
    logger.debug("   user score: score=%s" % User_Score)
    # TODO: Add actual processing logic based on user score



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
        logger.info("DEV=running file removed")

    if not os.path.isfile(RUNNING_FILE):
        create_running_file()
        start_process = True
    else:
        logger.error("bot already running! Will not start.")

    # Initalize
    next_refresh_time = 0

    while start_process and os.path.isfile(RUNNING_FILE):
        logger.debug("Start Main Loop")

        # Only refresh sublists and wiki settings once an hour
        if int(round(time.time())) > next_refresh_time:
            logger.info("REFRESH Start")
            accept_mod_invites()
            subList = []
            for subs in reddit.user.moderator_subreddits():
                SubName = str(subs).lower()
                get_subreddit_settings(SubName)
                if 'subsearchlist' in Settings['SubConfig'][SubName]:
                    subList.append(SubName)
            logger.debug("subList: %s" % subList)
            next_refresh_time = int(
                round(time.time())) + (60 * int(Settings['Config']['config_refresh_mins']))
            logger.info("REFRESH Completed")

        multireddits = build_multireddit_groups(subList)
        for multi in multireddits:
            #subreddit = reddit.subreddit(settings.REDDIT_SUBREDDIT)
            subreddit = reddit.subreddit('+'.join(multi))
            comment_stream = subreddit.stream.comments(pause_after=-1)
            submission_stream = subreddit.stream.submissions(pause_after=-1)

            # TODO: Process submssion stream
            # try:
            #  for submission in submission_stream:
            #    if submission is None:
            #       break
            #   #check_submission(submission)

            try:
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

        logger.debug("End Main Loop - Pause %s secs" %
                     Settings['Config']['main_loop_pause_secs'])
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
