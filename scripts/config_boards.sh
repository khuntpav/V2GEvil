#!/usr/bin/env bash
    
# Work for Ubuntu, because Ubuntu naming convention for external ethernet
# adapter is enx + MAC address without : (colon)
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

main() {
    # TODO: maybe implement it with getopt or getopts
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        print_help
        exit 0
    elif [[ "$1" == "-r" || "$1" == "--revert" ]]; then
        # TODO(khuntpav): Imlement function for revert
        # all setting from the interfaces
        revert_conf
        exit 0
    elif [[ "$1" == "-c" || "$1" == "--copy" ]]; then
        copy_env "$2"
        exit 0
    fi

    configure_boards
}

#######################################
# Function to get MAC addresses from user (interactive) for later use
# Globals:
#   MAC_CAR
#   MAC_STATION
# Arguments:
#   None
# Style of comment from: https://google.github.io/styleguide/shellguide.html
#######################################

get_MAC_addr() {
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

    # Delete colon (:) from MAC addresses
    MAC_CAR=$(echo "$MAC_CAR" | tr -d :)
    MAC_STATION=$(echo "$MAC_STATION" | tr -d :)
}

# Function for renaming interface
# @arg1 First positional argument current name of the interface
# @arg2 Second positional argument new name for the interface

rename_interface() {
    local interface
    local new_interface
    interface="$1"
    new_interface="$2"

	echo "Running function config interface: $interface"
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
    sudo ip addr add fe80::d237:45ff:fe88:b12a/127 dev "$ETH_CAR"
    sudo ip addr add fe80::d237:45ff:fe88:b12b/127 dev "$ETH_STATION"
}

configure_boards() {
    # Print available interface for the user
    ip link
    echo

    # Call the function to get MAC addresses
    get_MAC_addr

    echo "Configuration of interface: enx$MAC_CAR"
    rename_interface "enx$MAC_CAR" "$ETH_CAR"
   
    echo "Configuration of station interface: enx$MAC_STATION"
    rename_interface "enx$MAC_STATION" "$ETH_STATION"

    echo "Setting IPv6 addresses for both interfaces: $ETH_CAR and $ETH_STATION"
    set_ipv6_addr
}

# Function for spawning EVCC and SECC
copy_env() {
    if [[ -z "$1" ]]; then
        echo "Error, specify which .env you want to copy: evcc or secc"
        exit 1
    fi

    if [[ "$1" == "evcc" ]]; then
        # EVCC
        # Copy config file for EVCC to .env
        cp ~/V2G/repos/V2GEvial/config/env-evcc ~/V2G/repos/iso15118/.env\
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

revert_conf() {

    ip link
    get_MAC_addr
    
    # Rename interfaces back as they are like this by default
    rename_interface "$ETH_CAR" "enx$MAC_CAR"
    rename_interface "$ETH_STATION" "enx$MAC_STATION"
}


print_help() {
    
    echo "Help for this program. If no option is supplied,"\
         "the default option is to configure interfaces for V2G boards."
    echo
    
    echo "Usage: $0 [option...] [values...]"
    echo
    echo "   -r, --revert           revert configuration of interfaces"\
         "from default run of this program"
    echo "   -c , --copy      copy env file, \$name: evcc, secc"
    echo "   -h, --help             print this help"
}

#########################
# END Function definition
#########################


main "$@"; exit

