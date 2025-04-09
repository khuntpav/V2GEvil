#!/usr/bin/env bash
    
# Helpful script for implementation of ISO15118 by SwitchEV - Josev:
# https://github.com/SwitchEV/iso15118

###########################
#       Constants         #
###########################

ETH_STATION="eth_station" 


###########################
# START Function definition
###########################

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
# 	MAC_STATION
#   IFNAME_STATION
# Arguments:
#   None
# Style of comment from: https://google.github.io/styleguide/shellguide.html
#######################################
get_ifname_from_MAC() {

    read -p "Please enter MAC address for station: " MAC_STATION
    if [[ -z "$MAC_STATION" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

    IFNAME_STATION=$(ip -o link | grep "$MAC_STATION" | awk -F': ' '{print $2}')

}


#######################################
# Function to get interface names from user (interactive)
# Globals
#   IFNAME_STATION
# Arguments:
#   None
#######################################
get_ifname() {
	
    read -p "Please enter interface name for station: " IFNAME_STATION
    if [[ -z "$IFNAME_STATION" ]]; then
        echo "Error: Cannot be empty"
        exit 1
    fi

}

# Function for renaming interface
# @arg1 First positional argument current name of the interface
# @arg2 Second positional argument new name for the interface

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

set_ipv6_addr() {
    sudo ip addr add fe80::d237:45ff:fe88:b12b/127 dev "$ETH_STATION"
}

configure_board() {
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
   
    echo "Configuration of station interface: $IFNAME_STATION"
    rename_interface "$IFNAME_STATION" "$ETH_STATION"

    echo "Setting IPv6 addresses for both interface $ETH_STATION"
    set_ipv6_addr
}

# Function for spawning EVCC and SECC
copy_env() {
    if [[ -z "$1" ]]; then
        echo "Error, specify which .env you want to copy: evcc or secc"
        exit 1
    fi

    if [[ "$1" == "secc" ]]; then
        # SECC
        # Copy config file for SECC to .env
        cp ~/V2G/repos/V2GEvil/config/env-secc ~/V2G/repos/iso15118/.env     
        if (( $? != 0 )); then
            echo "Unable to copy env-secc to .env" >&2
            exit 1
        fi
    fi
}



print_help() {
    
    echo "Help for this program. If no option is supplied,"\
         "the default option is to configure interface for V2G board for EVSE."
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

