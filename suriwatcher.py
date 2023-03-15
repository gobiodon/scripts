#!/usr/bin/python3

import sys
import time
import os
import requests
import smtplib
import email.utils
from email.mime.text import MIMEText


# Script that monitors the suricata fast log and sends a notification when there is a new alert
# via ntfy or email. Start in the background like:
#   ~ python3 suriwatcher.py &
# or via systemd



# General settings
suricata_log 		= "/var/log/suricata/fast.log" # path to suricata fast log
mtype               = "email" # how do you wanna get notified? "ntfy" or "email", don't forget to set the variables below

# ntfy settings, only needed for mtype = ntfy
ntfy_auth_token     = "" # auth token for your ntfy user
ntfy_server         = "" # ntfy server, can be the offical one or self hosted
ntfy_topic          = "" # the ntfy topic

# email settings, only needed for mtype = email
email_from          = "" # "from" email address
email_to            = "" # to which address should I send the notifications?





def parse_logline(s):
    row = [ ]
    sline = s.split("[**]")
    row = [sline[1].strip(), sline[2].strip()]
    return row


def tail(logfile):
    logfile.seek(0,2)
    af_inode = os.stat(suricata_log).st_ino
    while True:
        try:
            line = logfile.readline()
            if not line:
                time.sleep(0.1)
                if os.path.isfile(suricata_log):
                    if os.stat(suricata_log).st_ino != af_inode:
                        yield "FILE_STATE_CHANGED"
                else:
                    break
                continue
            yield line
        except KeyboardInterrupt:
            print("Exit...")
            sys.exit()
        except ValueError:
            break
        except:
            logfile.close()

def ntfy_notification(token, server, topic, logmsg):
    requests.post("https://{0}/{1}".format(server, topic),
    data=logmsg,
    headers={
    "Authorization": "Bearer {0}".format(token)
    })

def mail_notification(logmsg):
    msg = MIMEText(logmsg)
    msg['To'] = email.utils.formataddr(("Suricata Admin", email_to))
    msg['From'] = email.utils.formataddr(("Suricata", email_from))
    msg['Subject'] = "Suricata Alert"
    server = smtplib.SMTP()
    server.connect('localhost', 25)
    try:
        server.sendmail(email_to, [email_to], msg.as_string())
    except Exception as e:
        print("Error: {0}".format(e))
    finally:
        server.quit()

def send_notification(mtype, msg):
    if mtype == "ntfy":
        ntfy_notification(ntfy_auth_token, ntfy_server, ntfy_topic, msg)
    elif mtype == "email":
        mail_notification(msg)
    else:
        print("Error: Please specify the way you want to get notified")
        sys.exit(1)






if __name__ == '__main__':
    
    print("Suriwatch started")
    while True:
        f = open(suricata_log,"r")
        loglines = tail(f)
        for line in loglines:
            try:
                send_notification(mtype, "Suricata Alert:\n{0}\n{1}".format(parse_logline(line)[0], parse_logline(line)[1]))
            except IndexError:
                        print("Logline has an invalid format, skip...")
            except KeyboardInterrupt:
                print("Exit...")
                sys.exit()
            except IOError:
                break
            except Exception as e:
                print("Exception: {0}".format(e))