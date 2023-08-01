#import logging
#from scapy.all import *
import logging
import rich_click as click

logger = logging.getLogger(__name__)

@click.group()
def sniffer_tools():
    """Tool related commands"""
    click.echo("Sniffer tools loaded successfully!")

@sniffer_tools.command(name="banner")
def banner():
    """Prints a hello message. Testing purposes only. Test if module is loaded correctly."""
    print("Hello, from sniffer module!")
    logger.debug("Hello, from sniffer module!")

@sniffer_tools.command(name="sniff")
@click.option("--interface", "-i", default="eth_car", help="Interface to sniff on, default: eth0")
def sniff(interface: str, mode: str = "pcap"):
    """Sniff packets"""
    print("Sniffing packets...")
    logger.debug(f"Sniffing packets on interface: {interface}")

