#!/usr/bin/env bash

# Helpful script for implementation of ISO15118 by SwitchEV - Josev:
# https://github.com/SwitchEV/iso15118

###########################
#       Constants         #
###########################

ETH_CAR="eth_car"

###########################
# START Function definition
###########################

#######################################
# Main function
# Globals:
#   None
# Arguments:
#   $1 - first positional argument, option for the script
#   $2 - second positional argument, value for the option, only for -c option
#   Options:
#   -h, --help      print help
#   -c, --copy      copy env file, $2: evcc, secc
#   -i, --ifname    configure boards using interface names
#                   instead of MAC addresses
#######################################
main() {
    # TODO: maybe implement it with getopt or getopts
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        print_help
        exit 0
    elif [[ "$1" == "-c" || "$1" == "--copy" ]]; then
        copy_env "$2"
        exit 0
	elif
		[[ "$1" == "-i" || "$1" == "--ifname" ]]; then
		configure_board true
        exit 0
    fi

    # By default config boards using MAC address as input from the user
    configure_board false
    exit 0
}


#######################################
# Function to get MAC addresses from user (interactive) and find the interface names for given MACs
# Globals
# 	MAC_CAR
#   IFNAME_CAR
# Arguments:
#   None
# Style of comment from: https://google.github.io/styleguide/shellguide.html
#######################################
get_ifname_from_MAC() {

    echo "get_ifname_from_MAC"

    read -p "Please enter MAC address for car: " MAC_CAR

    if [[ -z "$MAC_CAR" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi
    IFNAME_CAR=$(ip -o link | grep "$MAC_CAR" | awk -F': ' '{print $2}')

}

#######################################
# Function to get interface name from user
# Globals:
#   IFNAME_CAR
# Arguments:
#   None
#######################################
get_ifname() {

 	read -p "Please enter interface name for car: " IFNAME_CAR
    if [[ -z "$IFNAME_CAR" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

}


#######################################
# Function to rename interface
# Locals:
#   interface
#   new_interface
# Arguments:
#   $1 - current name of the interface
#   $2 - new name for the interface
#######################################
rename_interface() {
    local interface
    local new_interface
    interface="$1"
    new_interface="$2"
    
    echo "Running function for configuration of interface: $interface"
    echo "New name of the interface: $new_interface"

    sudo ip link set "$interface" down
    sudo ip link set "$interface" name "$new_interface" 
    sudo ip link set "$new_interface" up
}


#######################################
# Function to set static IPv6 address
# Globals:
#   ETH_CAR
# Arguments:
#   None
#######################################
set_ipv6_addr() {
    sudo ip addr add fe80::d237:45ff:fe88:b12a/127 dev "$ETH_CAR"
}


configure_board() {
    local ifname_flag
    ifname_flag="$1"
    
    # Print available interface for the user
    ip link
    echo

    if [[ "$ifname_flag" == "true" ]]; then
        get_ifname
    else
        # Call the function to get MAC addresses
        get_ifname_from_MAC
    fi

    echo "Configuration of interface: $IFNAME_CAR"
    rename_interface "$IFNAME_CAR" "$ETH_CAR"

    echo "Setting Link local IPv6 address for both interface: $ETH_CAR."
    set_ipv6_addr
}


#######################################
# Function to print help
# Globals:
#   None
# Arguments:
#   None
#######################################
copy_env() {

    if [[ -z "$1" ]]; then
        echo "Error, specify which .env you want to copy: evcc or secc"
        exit 1
    fi

    if [[ "$1" == "evcc" ]]; then
        # EVCC
        # Copy config file for EVCC to .env
        cp ~/V2G/repos/V2GEvil/config/env-evcc ~/V2G/repos/iso15118/.env\
            || { echo "Unable to copy .env-evcc to .env"; exit 1; }

}

#######################################
# Function to print help
# Globals:
#   None
# Arguments:
#   None
#######################################
print_help() {
    
    echo "Help for this program. If no option is supplied,"\
         "the default option is to configure interface for V2G board for EV/PEV."
    echo
    
    echo "Usage: $0 [option...] [values...]"
    echo
    echo "   -c , --copy      copy env file, \$name: secc"
    echo "   -h, --help             print this help"
}

#########################
# END Function definition
#########################


main "$@"; exit