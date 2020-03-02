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

# String in webdisptab after which new entries should be added
WEB_DISP_TAB_PATTERN="# Script inserted entries"

#############
# FUNCTIONS #
#############

function _create_backups() { #quickdoc: Creates backups of ACL files.
    cp "$WEB_DISP_TAB" "$BKP_WEB_DISP_TAB"
    cp "$SAP_ROUT_TAB" "$BKP_SAP_ROUT_TAB"
}

function _create_temp_files() { #quickdoc: Creates temporary files to store data.
    cp "$WEB_DISP_TAB" "$TMP_WEB_DISP_TAB"
    cp "$SAP_ROUT_TAB" "$TMP_SAP_ROUT_TAB"
    touch "$TMP_IPS" "$TMP_SIDS"
}

function _remove_temp_files() { #quickdoc: Removes temporary files used by the script.
    rm "$TMP_WEB_DISP_TAB" "$TMP_SAP_ROUT_TAB" "$TMP_IPS" "$TMP_SIDS"
}

function _check_valid_ipv4_address() { #quickdoc: Checks if an entered IPv4 address is valid or not.
    if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))([/]([0123456789]|1[0-9]|2[0-9]|3[0-2]))?$ && ! ("$1" =~ ^(([0])\.){3}([0])([/]([0123456789]|1[0-9]|2[0-9]|3[0-2]))?$) ]]
    then
	return 0
    else
	return 1
    fi
}

function _check_valid_sid() { #quickdoc: Checks if an entered SID is valid or not.
    if [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]$ ]]
    then
	return 0
    else
	return 1
    fi
}

function _check_sid_exists() { #quickdoc: Checks if an entered SID exists in the reference table.
    if grep -i -q "$1" "$SAP_ROUT_TAB"
    then
	return 0
    else
	return 1
    fi
}

function _get_system_details() { #quickdoc: Extracts system information from the SID reference table.
    # System information
    SYS_INFO=$(grep -i "$1" "$SAP_ROUT_TAB" | head -n 1)
    # Hostname
    HOST_NAME=$(echo "$SYS_INFO" | awk '{print $3}')
    # Dispatcher port
    DISP_PORT=$(echo "$SYS_INFO" | awk '{print $4}' | tr -d ',')
    # Gateway port
    GATW_PORT=$(echo "$SYS_INFO" | awk '{print $5}')
}

function _insert_entry_webdisptab() { #quickdoc: Inserts an entry into the temporary web dispatcher ACL file.
    sed -i -e "/$WEB_DISP_TAB_PATTERN/a\\" -e "$1" "$TMP_ROUT_TAB"
}

function _insert_entry_saprouttab() { #quickdoc: Inserts an entry into the router table.
    sed -i "\$a$1" "$TMP_ROUT_TAB"
}

function _remove_blank_lines() { #quickdoc: Removes blank lines from a file.
    sed -i "/^$/d" "$1"
}

function _update_webdisptab() { #quickdoc: Updates the entries in the webdisptab ACL file.
    cp "$TMP_WEB_DISP_TAB" "$WEB_DISP_TAB"
}
