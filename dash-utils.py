#!/usr/bin/env python3
# encoding=UTF-8
"""Methods that do things that the Meraki API cannot currently do.

This file will contain utilities that will work provided correct
Meraki dashboard user/pass/(tfa).
"""
import subprocess
import sys
import os
import time


def check_for_tshark():
    """Verify that tshark can be accessed from the command line."""
    # Add Wireshark program folder to PATH
    if sys.platform == 'win32':
        # In order to make sure tshark is in the windows PATH
        os.environ['PATH'] += ';C:\Program Files\Wireshark'

    # Print tshark version or else error out
    try:
        version_message = subprocess.Popen(
            ['tshark', '-v'], stdout=subprocess.PIPE).communicate()[0]
        # version message includes license, so let's take first line
        print(version_message.splitlines()[0].decode("UTF-8"))

    # If the tshark executable doesn't exist or isn't on path
    except FileNotFoundError:
        print("ERROR: Tshark is not installed"
              "\nOn some OSes, it comes bundled with Wireshark.")


def filter_pcap(pcap_in, pcap_filters, outfile_name=''):
    """Takes a pcap, filters it, and then outputs the result.

    This script is a python wrapper for tshark that takes a pcap and filters
    and returns the filtered pcap. Requires tshark to be installed.
    Usage: filtered_pcap = filter_pcap(pcap_in, pcap_filters)


    Args:
        pcap_in (*.pcap): A valid pcap file
        pcap_filters(string): a string of wireshark filters
        outfile_name (string, optional): Name of output file

    Returns:
        Output filtered pcap file
    """

    check_for_tshark()
    print("Filtering pcap...")

    pcap_in_name, ext = os.path.basename(pcap_in).split('.')
    if outfile_name:
        outfile_name = pcap_in_name + '-out.' + ext

    print("Input file: ", pcap_in, "\nFilters: ", pcap_filters)
    subprocess.call(['tshark',
                     '-n',
                     '-r', pcap_in,
                     '-Y', pcap_filters,
                     '-w', outfile_name],
                    shell=True)


def get_tcpdump_pcap(browser, network_id, interface,
                     duration=60, tcpdump_filter='', download_path='.'):
    """Download a pcap from a network

    Planned architecture:
        Given that the user has logged in, that we have the base_url from a
        network, and a MechanicalSoup browser object with the credentials:

        base_url = https://n<int>.meraki.com/<network-name>/n/<eid>
        browser.open(base_url + /manage/dashboard/tcpdump)

        # implement below
        set_tcpdump_prefs(browser, network_id, product, interface,
                          tcpdump_filter=<val>, duration=<val>)

    Args:
        browser (MechanicalSoup): Browser object that has user credentials.
        network_id (int): ID of device (from API) that we want to capture on
        interface (string): Interface to take pcap on

        duration (int): Seconds pcap should last.
        tcpdump_filter (string): A tcpdump (BPF) syntax string.
        download_path (string): Path where the pcap should be downloaded
          (This directory used if none specified)
    """

    pass


def set_tcpdump_prefs(browser, network_id, product, interface,
                      duration=60, tcpdump_filter=''):
    """Set the tcpdump settings to download a pcap from one device/interface

    Planned architecture:
        The 'All APs' interface is lossy, so won't be included as an option.

        1. Set the specific device by <network_id>
        2. Set the interface to <interface>
        3. Set output to 'Download .pcap file (for Wireshark)'
        4. Set Duration text field to <duration>
        5. Set filter expression to <tcpdump_filter>
        6. Set the pcap file name to <network name>-<interface>-<hhmmss>.pcap
        7. Submit the form

    Args:
        browser (MechanicalSoup): Browser object that has user credentials.
        network_id (int): ID of device (from API) that we want to capture on
        product (string): Two digit product code (i.e. MX, MS, MR, MV, MC)
        interface (string): Interface to take pcap on

        duration (int): Seconds pcap should last.
        tcpdump_filter (string): A tcpdump (BPF) syntax string.
    """

    # MS has ports that can be specified in a text field
    # Interface dict is based upon name on form in tcpdump page
    interface_dict = {
        'MX': {
            'Internet': 'wan0_sniff',
            'LAN': 'all_lan_sniff',
            'Site-to-Site VPN': 'vpn_sniff',
            'Client VPN': 'client_vpn',
            'Cellular': 'cellular_sniff'},
        'MR': {
            'Wireless': 'wireless_log',
            'Wired': 'wired_log',
            'LAN': 'wired_lan_log'},
        'MC': {
            'Wired': 'eth0',
            'Wireless': 'wlan0'},
        'MV': {
            'Wired': 'wired0'}
    }

    # There should be a way to get the current network_name from the HTML
    network_name = 'Pandora'

    # Probably goes above or sent to set_tcpdump_prefs instead of browser
    form = browser.select_form()
    form['interface_select'] = interface_dict[product][interface]
    # Valid values: ['direct', 'dload']
    form['output_select'] = 'dload'
    form['duration'] = duration
    form['filter_expression_input'] = tcpdump_filter
    form['filename'] = network_name + '-' + interface \
        + '-' + time.strftime("%H%M") + '.pcap'
    # id='start capture'
    form.choose_submit('commit')


def get_eventlogs():
    """Get the event logs for a network with filters

    """
    pass
