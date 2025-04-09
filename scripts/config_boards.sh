#!/usr/bin/env bash
    
# Helpful script for implementation of ISO15118 by SwitchEV - Josev:
# https://github.com/SwitchEV/iso15118

###########################
#       Constants         #
###########################

ETH_CAR="eth_car"           
ETH_STATION="eth_station" 


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
		configure_boards true
        exit 0
    fi

    # By default config boards using MAC address as input from the user
    configure_boards false
    exit 0
}

#######################################
# Function to get MAC addresses from user (interactive) and find the interface names for given MACs
# Globals
# 	MAC_CAR
# 	MAC_STATION
#   IFNAME_CAR
#   IFNAME_STATION
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

    read -p "Please enter MAC address for station: " MAC_STATION
    if [[ -z "$MAC_STATION" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

    IFNAME_CAR=$(ip -o link | grep "$MAC_CAR" | awk -F': ' '{print $2}')
    IFNAME_STATION=$(ip -o link | grep "$MAC_STATION" | awk -F': ' '{print $2}')

}

#######################################
# Function to get interface names from user (interactive)
# Globals
#   IFNAME_CAR
#   IFNAME_STATION
# Arguments:
#   None
#######################################
get_ifnames() {

 	read -p "Please enter interface name for car: " IFNAME_CAR
    if [[ -z "$IFNAME_CAR" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

    read -p "Please enter interface name for station: " IFNAME_STATION
    if [[ -z "$IFNAME_STATION" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

}

# Function for renaming interface
# @arg1 First positional argument current name of the interface
# @arg2 Second positional argument new name for the interface

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

# Function for setting static IPv6 for both interfaces: car and station 
# No arguments
# TODO: In future maybe allow IPv6 from args,
# TODO: but for now it's enough hardcoded

#######################################
# Function to set static IPv6 addresses for both interfaces
# Globals:
#   ETH_CAR
#   ETH_STATION
# Arguments:
#   None
#######################################
set_ipv6_addr() {
    sudo ip addr add fe80::d237:45ff:fe88:b12a/127 dev "$ETH_CAR"
    sudo ip addr add fe80::d237:45ff:fe88:b12b/127 dev "$ETH_STATION"
}


#######################################
# Function to configure boards
# Globals:
#   ETH_CAR
#   ETH_STATION
#   IFNAME_CAR
#   IFNAME_STATION
# Arguments:
#   $1 - flag to determine if we want to get interface names from user or MAC addresses
#     true - get interface names from user
#     false - get MAC addresses from user
#######################################
configure_boards() {
    local ifname_flag
    ifname_flag="$1"
    
    # Print available interface for the user
    ip link
    echo

    if [[ "$ifname_flag" == "true" ]]; then
        get_ifnames
    else
        # Call the function to get MAC addresses
        get_ifname_from_MAC
    fi

    echo "Configuration of interface: $IFNAME_CAR"
    rename_interface "$IFNAME_CAR" "$ETH_CAR"
   
    echo "Configuration of station interface: $IFNAME_STATION"
    rename_interface "$IFNAME_STATION" "$ETH_STATION"

    echo "Setting IPv6 addresses for both interfaces: $ETH_CAR and $ETH_STATION"
    set_ipv6_addr
}

#######################################
# Function to copy .env file
# Globals:
#   None
# Arguments:
#   $1 - name of the .env file to copy
#    evcc - copy env-evcc to .env directory
#    secc - copy env-secc to .env directory
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
        #if (( $? != 0 )); then
        #    echo "Unable to copy env-evcc to .env" >&2
        #    exit 1
        #fi
    elif [[ "$1" == "secc" ]]; then
        # SECC
        # Copy config file for SECC to .env
        cp ~/V2G/repos/V2GEvil/config/env-secc ~/V2G/repos/iso15118/.env     
        if (( $? != 0 )); then
            echo "Unable to copy env-secc to .env" >&2
            exit 1
        fi
    fi
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
         "the default option is to configure interfaces for V2G boards."
    echo
    
    echo "Usage: $0 [option...] [values...]"
    echo
    echo "   -c , --copy      copy env file, \$name: evcc, secc"
    echo "   -h, --help             print this help"
}

#########################
# END Function definition
#########################

# Call main function with all arguments
main "$@"; exit

