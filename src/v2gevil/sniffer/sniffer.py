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
def sniff():
    """Sniff packets"""
    print("Sniffing packets...")

#if __name__ == "__main__":
#    sniffer_tools()
