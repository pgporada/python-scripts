#!/usr/bin/python2
'''
description: Script that gathers a user/password from the pillar.
             This script is meant to be run with sudo privs instead of
             the entirety of another script being run with sudo privs.
             You can combine with with an /etc/sudoers.d/whatever entry
             to allow this script to be run without a password.
usage: ./retrieve-pillar-creds.py -r git -u whatever:jira:username -p whatever:jira:password
'''

from __future__ import print_function
import argparse
import os
import sys
import salt.config
import salt.client
import salt.loader


def get_args(argv=None):
    '''
    Parse arguments from the command line
    '''
    parser = argparse.ArgumentParser(
        description='Specify the type of credential you want to acquire')
    parser.add_argument('--role', '-r', help="--role git",
                        type=str, metavar="r", required=True)
    parser.add_argument('--pillar_user', '-u', help="--user whatever:jira:username",
                        type=str, metavar="u", required=True)
    parser.add_argument('--pillar_pass', '-p', help="--pass whatever:jira:password",
                        type=str, metavar="p", required=True)
    return parser.parse_args(argv)


def check_privileges():
    '''
    Checks if you're root or using sudo.
    '''
    if os.getuid() != 0:
        print("ERROR: You need to run this script with elevated privileges.")
        sys.exit(1)


def check_grains(role):
    '''
    We need to check that the minion has the 'G@roles:${ROLE}' grain assigned to it.
    '''
    if os.path.exists("/etc/salt/minion"):
        saltopts = salt.config.minion_config('/etc/salt/minion')
    else:
        print("ERROR: /etc/salt/minion file was not found, this is a bad thing")
        sys.exit(1)

    saltgrains = salt.loader.grains(saltopts)

    try:
        saltroles = saltgrains['roles']
    except BaseException:
        print("ERROR: The roles grain was not found.")
        print("       To debug for youself, run: `salt-call grains.get roles`")
        sys.exit(1)

    rolefound = False

    for i in saltroles:
        if i == role:
            rolefound = True

    if rolefound != True:
        print("ERROR: Role {} was not found on this minion.".format(role))
        sys.exit(1)


def get_credentials(saltuser, saltpass):
    '''
    Does a salt-call to get Jira credentials.
    '''
    call = salt.client.Caller()

    username = call.sminion.functions['pillar.get'](saltuser)
    if not username:
        print("ERROR: Could not retrieve username value from the pillar")
        sys.exit(1)

    password = call.sminion.functions['pillar.get'](saltpass)
    if not password:
        print("ERROR: Could not retrieve password value from the pillar")
        sys.exit(1)

    return username, password


def main():
    '''
    Main function that calls the rest of the functions
    '''
    defaultarg = None
    args = get_args(defaultarg)

    check_privileges()
    check_grains(args.role)
    creds = get_credentials(args.pillar_user, args.pillar_pass)
    print("{}".format(str(creds[0])))
    print("{}".format(str(creds[1])))


if __name__ == "__main__":
    main()
