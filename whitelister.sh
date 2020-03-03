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
WEBDISPTAB="/usr/sap/WD2/whitelist/webdisptab_test"

# Router table file
SAPROUTTAB="/usr/sap/WD2/whitelist/saprouttab_test"

# Temporary web dispatcher file
TMP_WEBDISPTAB="/tmp/$SCRIPT_NAME-webdisptab.temp"

# Temporary router table file
TMP_SAPROUTTAB="/tmp/$SCRIPT_NAME-saprouttab.temp"

# Temporary file to store IP addresses in
TMP_IPS="/tmp/$SCRIPT_NAME-ips.temp"

# Temporary file to store SIDs in
TMP_SIDS="/tmp/$SCRIPT_NAME-sids.temp"

# Backup of web dispatcher ACL file
BKP_WEBDISPTAB="$WEBDISPTAB-$SYS_TIME-$(echo $SYS_DATE | tr '/' '.').backup"

# Backup of router table file
BKP_SAPROUTTAB="$SAPROUTTAB-$SYS_TIME-$(echo $SYS_DATE | tr '/' '.').backup"

# PID of other running instance (if any)
if [ -f "$LOCK_FILE" ]
then
    RUN_PID=$(cat "$LOCK_FILE" | tr -d '\n')
fi

# String in webdisptab after which new entries should be added
WEBDISPTAB_PATTERN="# Script inserted entries"

#############
# FUNCTIONS #
#############

function _create_backups() { #quickdoc: Creates backups of ACL files.
    cp "$WEBDISPTAB" "$BKP_WEBDISPTAB"
    cp "$SAPROUTTAB" "$BKP_SAPROUTTAB"
}

function _create_temp_files() { #quickdoc: Creates temporary files to store data.
    cp "$WEBDISPTAB" "$TMP_WEBDISPTAB"
    cp "$SAPROUTTAB" "$TMP_SAPROUTTAB"
    touch "$TMP_IPS" "$TMP_SIDS"
}

function _remove_temp_files() { #quickdoc: Removes temporary files used by the script.
    rm "$TMP_WEBDISPTAB" "$TMP_SAPROUTTAB" "$TMP_IPS" "$TMP_SIDS"
}

function _check_valid_ipv4_address() { #quickdoc: Checks if an entered IPv4 address is valid or not.
    if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))([/]([0123456789]|1[0-9]|2[0-9]|3[0-2]))?$ && ! ("$1" =~ ^(([0])\.){3}([0])([/]([0123456789]|1[0-9]|2[0-9]|3[0-2]))?$) ]]
    then
	return 0
    else
	return 1
    fi
}

function _duplicate_ip_in_session() { #quickdoc": Checks whether an IP address was already entered in the current session.
    if grep -Eq "(^|\s)${1}($|\s)" "$TMP_IPS"
    then
	return 0
    else
	return 1
    fi
}

function duplicate_sid_in_session() { #quickdoc: Checks whether an entered SID was already entered in the current session.
    if grep -Eiq "(^|\s)${1}($|\s)" "$TMP_SIDS"
    then
	return 0
    else
	return 1
    fi
}

function _duplicate_entry_in_webdisptab() { #quickdoc: Checks whether information entered already exists in the webdisptab file.
    if grep -Eq "(^|\s)${1}($|\s)" "$TMP_WEBDISPTAB"
    then
	return 0
    else
	return 1
}

function _duplicate_entry_in_saprouttab() { #quickdoc: Checks whether information entered already exists in the saprouttab file.
    if grep -Eq "(^|\s)${1}($|\s)" "$TMP_SAPROUTTAB"
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
    if grep -i -q "$1" "$SAPROUTTAB"
    then
	return 0
    else
	return 1
    fi
}

function _get_system_details() { #quickdoc: Extracts system information from the SID reference table.
    # System information
    SYS_INFO=$(grep -i "$1" "$SAPROUTTAB" | head -n 1)
    # Hostname
    HOST_NAME=$(echo "$SYS_INFO" | awk '{print $3}')
    # Dispatcher port
    DISP_PORT=$(echo "$SYS_INFO" | awk '{print $4}' | tr -d ',')
    # Gateway port
    GATW_PORT=$(echo "$SYS_INFO" | awk '{print $5}')
}

function _insert_entry_webdisptab() { #quickdoc: Inserts an entry into the temporary web dispatcher ACL file.
    sed -i -e "/$WEBDISPTAB_PATTERN/a\\" -e "$1" "$TMP_WEBDISPTAB"
}

function _insert_entry_saprouttab() { #quickdoc: Inserts an entry into the router table.
    sed -i "\$a$1" "$TMP_SAPROUTTAB"
}

function _remove_blank_lines() { #quickdoc: Removes blank lines from a file.
    sed -i "/^$/d" "$1"
}

function _update_webdisptab() { #quickdoc: Updates the entries in the webdisptab ACL file.
    cat "$TMP_WEBDISPTAB" > "$WEBDISPTAB"
}

function _update_saprouttab() { #quickdoc: Updates the entries in the router table file.
    cat "$TMP_SAPROUTTAB" > "$SAPROUTTAB"
}

function _whitelister() { #quickdoc: Main whitelisting function.

    ###################
    # LOCAL VARIABLES #
    ###################

    # IP address
    local _ip_address
    # SID
    local _sid
    # Employee ID
    local _employee_id
    # Entry information
    local _entry_info
    # webdisptab entry format
    local _webdisptab_entry
    # saprouttab entry format
    local _saprouttab_entry

    # Create backups
    _create_backups

    echo "Press Ctrl-C at any time to exit the script."

    # Create temporary files
    _create_temp_files

    # Read IP addresses
    echo "Enter the IP addresses [Press Ctrl-D when you're done]:"
    while read _ip_address
    do
	if _check_valid_ipv4_address "$_ip_address"
	then
	    echo "$_ip_address" >> "$TMP_IPS"
	else
	    echo "INVALID IP ADDRESS."
	fi
    done

    # Check if user has pressed Ctrl-D without entering any IP addresses
    if [ $(wc -l < "$TMP_IPS") -eq 0 ]
    then
	echo "No IP addresses entered. Cleaning temporary files and quitting..."
	_remove_temp_files
	exit 1
    fi

    # Check choice of ACL file
    if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 3 ]
    then
	# Read SIDs
	echo "Enter the SIDs [Press Ctrl-D when you're done]:"
	while read _sid
	do
	    if _check_valid_sid "$_sid"
	    then
		echo "$SID" >> "$TMP_SIDS"
	    else
		echo "INVALID SID"
	    fi
	done

	# Check if user has pressed Ctrl-D without entering any SIDs
	if [ $(wc -l < "$TMP_SIDS") -eq 0 ]
	then
	    echo "No SIDs entered. Cleaning temporary files and quitting..."
	    _remove_temp_files
	    exit 1
	fi
    fi

    # Read employee ID
    while :
    do
	echo "Enter employee ID:"
	read _employee_id

	# Enforce that employee id should be non-empty
	if [ -z "$_employee_id" ]
	then
	    echo "Employee ID cannot be empty."
	else
	    break
	fi
    done

    # Read entry information
    while :
    do
	echo "Enter entry information:"
	read _entry_info

	# Enforce that entry information should be non-empty
	if [ -z "$_entry_info" ]
	then
	    echo "Entry information cannot be empty."
	else
	    break
	fi
    done

    # Insert entry
    while read _ip_address
    do
	if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 2 ]
	then
	    _webdisptab_entry="P /*\t*\t*$_ip_address\t*\t# Entry:\t$_employee_id\t$SYS_DATE\t$_entry_info"
	    _insert_entry_webdisptab "$_webdisptab_entry"
	fi

	if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 3 ]
	then
	    while read _sid
	    do
		_get_system_details "$_sid"
		_saprouttab_entry="P\t$_ip_address\t$HOST_NAME\t$DISP_PORT\t# Entry: $_employee_id $SYS_DATE $_entry_info"
		_insert_entry_saprouttab "$_saprouttab_entry"
		_saprouttab_entry="P\t$_ip_address\t$HOST_NAME\t$GATW_PORT\t# Entry: $_employee_id $SYS_DATE $_entry_info"
		_insert_entry_saprouttab "$_saprouttab_entry"
	    done < "$TMP_SIDS"
	fi
    done < "$TMP_IPS"

    # Remove blank lines

    # Update webdisptab and saprouttab
    _update_webdisptab
    _update_saprouttab

    # Remove temporary files
    _remove_temp_files
}

################
# MAIN SECTION #
################

# Banner
echo -e "####################
#  WHITELISTER.SH  #
####################\n"

# Prompt user for choice of ACL
while :
do
    echo -e "Which files would you like to make entries into?\n"

    echo "1. Both (webdisptab and saprouttab)."
    echo "2. Only web dispatcher (webdisptab)."
    echo "3. Only sap router table (saprouttab)."

    echo -en "\n> "
    read -n 1 ACL_CHOICE

    echo ""

    if [ -z "$ACL_CHOICE" ]
    then
	echo -e "\nPlease make a choice.\n"
    else
	break
    fi
done

# Call main whitelister process
_whitelister
