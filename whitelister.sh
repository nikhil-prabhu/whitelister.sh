#!/usr/bin/env bash

####################################################################################
#                                                                                  #
#                               WHITELISTER.SH                                     #
#                               --------------                                     #
#                                                                                  #
#   whitelister.sh is a (mostly) POSIX compliant BASH Shell Script that can        #
#   be used to internally whitelist 3rd party IP addresses by making entries       #
#   into one or more types of access control list (ACL) files. This version        #
#   of the script is specifically tailored for use by members of SAP ICC's RAC     #
#   team, to whitelist the IP addresses of SAP's partners by making appropriate    #
#   entries into the "webdisptab" and "saprouttab" files. Documentation will be    #
#   available in the README.md file in project's root directory.                   #
#                                                                                  #
#   The script is designed to be as portable and POSIX compliant as possible.      #
#   The conventions followed in this script can be found at:                       #
#                                                                                  #
#                  https://github.com/icy/bash-coding-style                        #
#                                                                                  #
#                                                                                  #
####################################################################################

####################
# GLOBAL VARIABLES #
####################

# Name of the script
SCRIPT_NAME="$(basename -- $0)"

# Current system time: format - DD/MM/YYYY
SYS_DATE=$(date +'%d/%m/%Y')

# Current system time: format - H:M:S (24 hour)
SYS_TIME=$(date +'%H:%M:%S')

# Current process id
CURRENT_PID=$$

# Lock file
LOCK_FILE="/tmp/$SCRIPT_NAME.lock"

# Web dispatcher ACL file
WEB_DISP_TAB="/usr/sap/WD2/whitelist/webdisptab_test"

# Router table file
SAP_ROUT_TAB="/usr/sap/WD2/whitelist/saprouttab_test"

# Temporary web dispatcher file
TMP_WEB_DISP_TAB="/tmp/$SCRIPT_NAME-webdisptab.temp"

# Temporary router table file
TMP_SAP_ROUT_TAB="/tmp/$SCRIPT_NAME-saprouttab.temp"

# Temporary file to store IP addresses in
TMP_IPS="/tmp/$SCRIPT_NAME-ips.temp"

# Temporary file to store SIDs in
TMP_SIDS="/tmp/$SCRIPT_NAME-sids.temp"

# Backup of web dispatcher ACL file
BKP_WEB_DISP_TAB="$WEB_DISP_TAB-$SYS_TIME-$(echo $SYS_DATE | tr '/' '.').backup"

# Backup of router table file
BKP_SAP_ROUT_TAB="$SAP_ROUT_TAB-$SYS_TIME-$(echo $SYS_DATE | tr '/' '.').backup"

# PID of other running instance (if any)
if [ -f "$LOCKFILE" ]
then
    RUN_PID=$(cat "$LOCKFILE" | tr -d '\n')
fi

#############
# FUNCTIONS #
#############

function _create_backups() { #doc: Creates backups of ACL files.
    cp "$WEB_DISP_TAB" "$BKP_WEB_DISP_TAB"
    cp "$SAP_ROUT_TAB" "$BKP_SAP_ROUT_TAB"
}

function _create_temp_files() { #doc: Creates temporary files to store data.
    cp "$WEB_DISP_TAB" "$TMP_WEB_DISP_TAB"
    cp "$SAP_ROUT_TAB" "$TMP_SAP_ROUT_TAB"
    touch "$TMP_IPS" "$TMP_SIDS"
}

function _remove_temp_files() { #doc: Removes temporary files used by the script.
    rm "$TMP_WEB_DISP_TAB" "$TMP_SAP_ROUT_TAB" "$TMP_IPS" "$TMP_SIDS"
}
