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
####################################################################################

##########################
# COMMAND LINE ARGUMENTS #
##########################

while getopts ":d:" _args
do
    case $_args in
	# Debugging mode
	d) DEBUG=$OPTARG;;
    esac
done

####################
# GLOBAL VARIABLES #
####################

# whitelister.sh version
VERSION=1.2.0

# Name of the script
SCRIPT_NAME="$(basename -- $0)"

# Path where script is stored
SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

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

# String in webdisptab after which new entries should be added
WEBDISPTAB_PATTERN="# Script inserted entries"

# Turn on debug mode
if [[ "$DEBUG" =~ ^ebug$ ]]
then
    DEBUG_LOG="/tmp/$SCRIPT_NAME-$(echo $SYS_DATE | tr '/' '.')-$SYS_TIME.log"
    PLATFORM_INFO="/tmp/$SCRIPT_NAME-$(echo $SYS_DATE | tr '/' '.')-$SYS_TIME.platforminfo"
    DEBUG_TARBALL="$SCRIPT_PATH/$SCRIPT_NAME-$(echo $SYS_DATE | tr '/' '.')-$(echo $SYS_TIME | tr ':' '.').tar"
else
    DEBUG_LOG="/dev/null"
fi

# Colors
RESET='\033[0m'
BLINK='\033[5m'
BOLD='\033[1m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'

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

function _lock_instance() { #quickdoc: Locks the current script instance.
    touch "$LOCK_FILE"
}

function _remove_temp_files() { #quickdoc: Removes temporary files used by the script.
    rm "$TMP_WEBDISPTAB" "$TMP_SAPROUTTAB" "$TMP_IPS" "$TMP_SIDS"
}

function _remove_lock() { #quickdoc: Removes the script instance lock.
    rm "$LOCK_FILE"
}

function _partner_exists() { #quickdoc: Checks whether a partner already has entries in the file(s).
    if grep -Eq "(^|\s)##-- ${1}:($|\s)" "$2"
    then
	return 0
    else
	return 1
    fi
}

function _valid_ipv4_address() { #quickdoc: Checks if an entered IPv4 address is valid or not.
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

function _duplicate_sid_in_session() { #quickdoc: Checks whether an entered SID was already entered in the current session.
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
    fi
}

function _duplicate_entry_in_saprouttab() { #quickdoc: Checks whether information entered already exists in the saprouttab file.
    if grep -iq "$1    $2" "$TMP_SAPROUTTAB"
    then
	return 0
    else
	return 1
    fi
}

function _valid_sid() { #quickdoc: Checks if an entered SID is valid or not.
    if [[ "$1" =~ ^[A-Za-z0-9]{3}$ ]]
    then
	return 0
    else
	return 1
    fi
}

function _sid_exists() { #quickdoc: Checks if an entered SID exists in the reference table.
    if grep -i -q "$1:" "$SAPROUTTAB"
    then
	return 0
    else
	return 1
    fi
}

function _valid_email() { #quickdoc: Checks if en entered email id is valid or not.
    if [[ "$1" =~ ^(.*[@].*\..*)$ ]]
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
    # If entry already exists, append to entry
    if grep -Eq "##-- $2: .* --##" "$TMP_WEBDISPTAB"
    then
	sed -i -e "/##-- $2: .* --##/a\\" -e "$1" "$TMP_WEBDISPTAB"
    else
	sed -i -e "/$WEBDISPTAB_PATTERN/a\\" -e "##-- $2: $3 --##" "$TMP_WEBDISPTAB"
	sed -i -e "/##-- $2: .* --##/a\\" -e "$1" "$TMP_WEBDISPTAB"
    fi
}

function _insert_entry_saprouttab() { #quickdoc: Inserts an entry into the router table.
    # If entry already exists, append to entry
    if grep -Eq "##-- $3: .* --##" "$TMP_SAPROUTTAB"
    then
	sed -i -e "/##-- $3: .* --##/a\\" -e "$1" "$TMP_SAPROUTTAB"
    else
	sed -i -e "\$a##-- $3: $4 --##" "$TMP_SAPROUTTAB"
	sed -i -e "/##-- $3: .* --##/a\\" -e "$1" "$TMP_SAPROUTTAB"
    fi
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

function _detect_init_system() { #quickdoc: Detects type of init system in use.
    if [[ `systemctl` =~ -\.mount ]] 2> /dev/null
    then
	# systemd
	INIT_SYSTEM="systemd"
    elif [[ -f "/etc/init.d/cron" ]] && [[ ! -h "/etc/init.d/cron" ]]
    then
	# SysV
	INIT_SYSTEM="SysV"
    fi
}

function _reload_saprouter() { #quickdoc: Reloads the saprouter service.
    if [ $INIT_SYSTEM = "systemd" ]
    then
	sudo -n systemctl restart saprouter &> /dev/null
    else
	saprouter reload &> /dev/null
    fi
}

function _generate_debug_tarball() { #quickdoc: Generates a tarball with debugging logs.
    echo "whitelister.sh version: $VERSION" > "$PLATFORM_INFO" 2>&1
    cat /etc/*-release >> "$PLATFORM_INFO" 2>&1
    awk --version >> "$PLATFORM_INFO" 2>&1
    sed --version >> "$PLATFORM_INFO" 2>&1
    tar cvf "$DEBUG_TARBALL" "$DEBUG_LOG" "$PLATFORM_INFO" &> /dev/null
}

function _whitelister() { #quickdoc: Main whitelisting function.

    ###################
    # LOCAL VARIABLES #
    ###################

    # Certification ID
    local _certification_id
    # Partner name
    local _partner_name
    # IP address
    local _ip_address
    # SID
    local _sid
    # Employee ID
    local _employee_id
    # Person who requested the entry
    local _requested_by
    # Consultant contact email id
    local _consultant_email
    # webdisptab entry format
    local _webdisptab_entry
    # saprouttab entry format
    local _saprouttab_entry

    # Create backups
    _create_backups

    # Create temporary files
    _create_temp_files

    # Read certification ID
    while :
    do
	echo -e "\n${BOLD}Enter the certification ID:${RESET}\n"
	read _certification_id
	if [[ "$_certification_id" =~ ^[0-9]+$ ]]
	then
	    break
	else
	    echo -e "${YELLOW}Certification ID can only contain numbers.${RESET}\n"
	fi
    done

    # Read partner name
    if _partner_exists "$_certification_id" "$TMP_WEBDISPTAB" && _partner_exists "$_certification_id" "$TMP_SAPROUTTAB"
    then
	_partner_name=$(sed -n -e "s/^.*.${_certification_id}: //p" "$TMP_WEBDISPTAB" | tr -d "\-\-##")
	echo -e "\n${GREEN}Identified partner as ${_partner_name}using certification ID $_certification_id.${RESET}\n"
    elif _partner_exists "$_certification_id" "$TMP_SAPROUTTAB"
    then
	_partner_name=$(sed -n -e "s/^.*.${_certification_id}: //p" "$TMP_SAPROUTTAB" | tr -d "\-\-##")
	echo -e "\n${GREEN}Identified partner as ${_partner_name}using certification ID $_certification_id.${RESET}\n"
    elif _partner_exists "$_certification_id" "$TMP_WEBDISPTAB"
    then
	_partner_name=$(sed -n -e "s/^.*.${_certification_id}: //p" "$TMP_WEBDISPTAB" | tr -d "\-\-##")
	echo -e "\n${GREEN}Identified partner as ${_partner_name}using certification ID $_certification_id.${RESET}\n"
    else
	while :
	do
	    echo -e "\n${YELLOW}Partner name could not be identified using certification ID.${RESET}"
	    echo -e "\n${BOLD}Enter the partner name:${RESET}\n"
	    read _partner_name

	    # Enforce that partner name should be non-empty
	    if [ -z "$_partner_name" ]
	    then
		echo -e "\n${YELLOW}Partner name cannot be empty.${RESET}\n"
	    else
		break
	    fi
	done
    fi

    echo ""

    # Read IP addresses
    echo -e "${BOLD}Enter the IP addresses [Press Ctrl-D when you're done]:${RESET}\n"
    while read _ip_address
    do
	if _valid_ipv4_address "$_ip_address"
	then
	    if _duplicate_ip_in_session "$_ip_address"
	    then
		echo -e "${YELLOW}You've already entered this IP address in the current session. Ignoring.${RESET}"
	    else
		if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 2 ]
		then
		    if _duplicate_entry_in_webdisptab "$_ip_address"
		    then
			echo -e "${YELLOW}An entry with IP address $_ip_address already exists in the webdisptab file. Ignoring.${RESET}"
		    else
			echo "$_ip_address" >> "$TMP_IPS"
		    fi
		else
		    echo "$_ip_address" >> "$TMP_IPS"
		fi
	    fi
	else
	    echo -e "${YELLOW}Invalid IP address: $_ip_address. Ignoring.${RESET}"
	fi
    done

    # Check if user has pressed Ctrl-D without entering any IP addresses
    if [ $(wc -l < "$TMP_IPS") -eq 0 ]
    then
	echo -e "${YELLOW}No IP addresses entered. Cleaning temporary files and quitting...${RESET}\n"
	_remove_temp_files
	_remove_lock
	exit 1
    fi

    echo ""
    
    # Check choice of ACL file
    if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 3 ]
    then
	# Read SIDs
	echo -e "${BOLD}Enter the SIDs [Press Ctrl-D when you're done]:${RESET}\n"
	while read _sid
	do
	    if _valid_sid "$_sid"
	    then
		if _sid_exists "$_sid"
		then
		    if _duplicate_sid_in_session "$_sid"
		    then
			echo -e "${YELLOW}You've already entered this SID in the current session. Ignoring.${RESET}"
		    else
			echo "$_sid" >> "$TMP_SIDS"
		    fi
		else
		    echo -e "${YELLOW}The SID $_sid does not exist in the saprouttab reference table. Ignoring.${RESET}"
		fi
	    else
		echo -e "${YELLOW}Invalid SID: $_sid. Ignoring.${RESET}"
	    fi
	done

	# Check if user has pressed Ctrl-D without entering any SIDs
	if [ $(wc -l < "$TMP_SIDS") -eq 0 ]
	then
	    echo -e "${YELLOW}No SIDs entered. Cleaning temporary files and quitting...${RESET}"
	    _remove_temp_files
	    _remove_lock
	    exit 1
	fi
    fi

    echo ""

    # Read employee ID
    while :
    do
	echo -e "${BOLD}Enter employee ID:${RESET}\n"
	read _employee_id

	# Enforce that employee id should be non-empty
	if [ -z "$_employee_id" ]
	then
	    echo -e "${YELLOW}Employee ID cannot be empty.${RESET}\n"
	elif [[ ! ("$_employee_id" =~ ^[idcIDC][0-9]{6}$) ]]
	then
	    echo -e "${YELLOW}Invalid employee ID $_employee_id.${RESET}\n"
	else
	    break
	fi
    done

    echo ""

    # Read name of person who requested entry
    echo -e "${BOLD}Entry requested by:${RESET}\n"
    read _requested_by

    echo ""

    # Read email id of technical consultant
    while :
    do
	echo -e "${BOLD}Enter email id of technical consultant:${RESET}\n"
	read _consultant_email

	# Enforce that email id should be non-empty
	if [ -z "$_consultant_email" ]
	then
	    echo -e "${YELLOW}Email id cannot be empty.${RESET}\n"
	else
	    # Check if email id is valid
	    if _valid_email "$_consultant_email"
	    then
		break
	    else
		echo -e "${YELLOW}Please enter a valid email id.${RESET}\n"
	    fi
	fi
    done

    # Insert entry
    while read _ip_address
    do
	if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 2 ]
	then
	    _webdisptab_entry="P    /*    *    *    $_ip_address    *    # Entry: $_employee_id | $SYS_DATE | $_requested_by | $_consultant_email"
	    _insert_entry_webdisptab "$_webdisptab_entry" "$_certification_id" "$_partner_name"
	    _ret=$?
	    if [ $_ret -ne 0 ]
	    then
		break
	    fi
	fi

	if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 3 ]
	then
	    while read _sid
	    do
		_get_system_details "$_sid"
		if _duplicate_entry_in_saprouttab "$_ip_address" "$HOST_NAME"
		then
		    echo -e "${YELLOW}An entry with IP address $_ip_address and hostname $HOST_NAME already exists in the router table. Ignoring.${RESET}"
		else
		    _saprouttab_entry="P    $_ip_address    $HOST_NAME    $DISP_PORT    # Entry: $_employee_id | $SYS_DATE | $_requested_by | $_consultant_email"
		    _insert_entry_saprouttab "$_saprouttab_entry" "$HOST_NAME" "$_certification_id" "$_partner_name"
		    _ret=$?
		    if [ $_ret -ne 0 ]
		    then
			break
		    fi
		    _saprouttab_entry="P    $_ip_address    $HOST_NAME    $GATW_PORT    # Entry: $_employee_id | $SYS_DATE | $_requested_by | $_consultant_email"
		    _insert_entry_saprouttab "$_saprouttab_entry" "$HOST_NAME" "$_certification_id" "$_partner_name"
		    _ret=$?
		    if [ $_ret -ne 0 ]
		    then
			break
		    fi
		fi
	    done < "$TMP_SIDS"
	fi
    done < "$TMP_IPS"

    if [ $_ret -ne 0 ]
    then
	echo -e "\n${YELLOW}An unknown error occured. (Error code: $_ret).${RESET}\n"
	_remove_temp_files
	_remove_lock
	exit 1
    else
	# Remove blank lines
	_remove_blank_lines "$TMP_WEBDISPTAB"
	_remove_blank_lines "$TMP_SAPROUTTAB"

	# Update webdisptab and saprouttab
	_update_webdisptab
	_update_saprouttab

	if [ "$ACL_CHOICE" -eq 1 ]
	then
	    echo -e "\n${GREEN}Entries added into webdisptab and saprouttab successfully.${RESET}\n"
	elif [ "$ACL_CHOICE" -eq 2 ]
	then
	    echo -e "\n${GREEN}Entries added into webdisptab successfully.${RESET}\n"
	else
	    echo -e "\n${GREEN}Entries added into saprouttab successfully.${RESET}\n"
	fi
	
	# Reload saprouter
	if [ "$ACL_CHOICE" -eq 1 ] || [ "$ACL_CHOICE" -eq 3 ]
	then
	    _detect_init_system
	    echo -e "${BOLD}Reloading saprouter... (Detected init system: $INIT_SYSTEM)${RESET}\n"
	    _reload_saprouter
	    local _ret="$?"
	    if [ "$_ret" -eq 0 ]
	    then
		echo -e "${GREEN}saprouter reloaded.${RESET}\n"
	    else
		echo -e "${YELLOW}Error. saprouter exited with status $_ret.${RESET}\n"
	    fi
	fi
    fi

    # Remove temporary files
    _remove_temp_files

    # Remove script instance lock
    _remove_lock
}

######################
# INTERRUPT HANDLING #
######################

# Remove temporary files on interrupt
trap "echo -e \"\n${YELLOW}Script interrupted. Removing temporary files and quitting...${RESET}\n\" ; _remove_temp_files ; _remove_lock ; exec 2> /dev/tty ; exit 1" SIGINT SIGTERM

################
# MAIN SECTION #
################

# Discard/write errors to log file.
exec 2> "$DEBUG_LOG"

# Banner
echo -e "\n       ${GREEN}####################${RESET}"
echo -e "       ${GREEN}#  WHITELISTER.SH  #${RESET}"
echo -e "       ${GREEN}####################\n${RESET}"

# Display debugging information in terminal
if [[ "$DEBUG" =~ ^ebug$ ]]
then
    echo -e "       ${YELLOW}-- DEBUGGING MODE --${RESET}\n"
    set -x
fi

echo -e "${BLINK}Press Ctrl-C at any time to exit the script.${RESET}\n"

# Check if another instance of the script is running
if [ -f "$LOCK_FILE" ]
then
    echo -e "${YELLOW}Error. Another instance of this script is already running. Refusing to continue.\n
Running more than one instance of this script at a time could potentially cause malformed or corrupted entries in the ACL files.\n
If you're sure of what you're doing and want to continue, delete the file '$LOCK_FILE' and run the script again.${RESET}\n"
    exit 1
else
    # Lock current instance of the script
    _lock_instance
    # Prompt user for choice of ACL
    while :
    do
	echo -e "${BOLD}Which files would you like to make entries into?${RESET}\n"

	echo -e "${BOLD}1.${RESET} Both (webdisptab and saprouttab)."
	echo -e "${BOLD}2.${RESET} Only web dispatcher (webdisptab)."
	echo -e "${BOLD}3.${RESET} Only sap router table (saprouttab)."

	echo -en "\n${BOLD}>${RESET} "
	read -n 1 ACL_CHOICE

	echo -e "\n"

	if [ -z "$ACL_CHOICE" ] || [[ ! ("$ACL_CHOICE" =~ ^[123]$) ]]
	then
	    echo -e "\nPlease make a choice.\n"
	else
	    break
	fi
    done

    # Call main whitelister process
    _whitelister

    # Generate debugging information tarball
    _generate_debug_tarball

    if [[ "$DEBUG" =~ ^ebug$ ]]
    then
	echo -e "${YELLOW}Debugging information tarball generated in $DEBUG_TARBALL${RESET}\n"
    fi
fi
