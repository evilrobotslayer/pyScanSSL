#!/usr/bin/env python3.4

__author__ = "George M. Grindlinger"
__version__ = "0.2"
__email__ = "georgeg@evilrobotslayer.com"
__status__ = "Development"
__doc__ = "Scan hosts and report back on SSL expiration"


import argparse
import logging
import datetime
import socket
import certifi
import netaddr 
import sys
from OpenSSL import SSL


# Initialize logging and debugging code
def dump(obj):
   for attr in dir(obj):
       if hasattr( obj, attr ):
           print( "obj.%s = %s" % (attr, getattr(obj, attr)))

log = logging.getLogger(__name__)


TIMEOUT = 15


# Initialize and define argument parsing
argParser = argparse.ArgumentParser(
    description='Scan a host/network range checking SSL certificates',
    epilog="This program utilizes raw sockets and MUST be run as root.")
argParser.add_argument('-H', '--host', nargs='+', dest='hosts', help='Specify a space delimited list of hosts to scan')
argParser.add_argument('-N', '--net', nargs='+', dest='nets', help='Specify a space delimited list of network ranges to scan')
args = argParser.parse_args()


def get_host_certificate(host, port=443):
    ip_addr = socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#    sock = socket.socket()
    sock.settimeout(TIMEOUT)
    context = SSL.Context(SSL.SSLv23_METHOD)
#    context = SSL.Context(SSL.TLSv1_METHOD)
#    context.set_options(SSL.OP_NO_SSLv2)
#    context.set_options(SSL.OP_NO_SSLv3)
    context.set_timeout(TIMEOUT)
    context.load_verify_locations(certifi.where().encode(encoding="ascii"), None)
    ssl_sock = SSL.Connection(context, sock)
    try :
        ssl_sock.connect((ip_addr, port))
        ssl_sock.setblocking(1)
        ssl_sock.do_handshake()
    except SSL.Error:
        print("SSL Error: Socket connected to port, maybe host not using SSL?\nMoving on...\n")
        sys.stdout.flush()
        return None
    except socket.timeout:
        print("Connection Timeout Exceeded: Host may be dead or not listening\nMoving on...\n")
        sys.stdout.flush()
        return None
    except OSError as e:
        if (e.errno == 111):
            print("OS Error encountered: " + e.strerror + "\nMoving on...\n")
            sys.stdout.flush()
            return None
    else:
        return ssl_sock.get_peer_certificate()

def check_host_certificate(host):
    print("Hostname: " + str(host))
    cert = get_host_certificate(host)
    if (cert == None):
        return None
    cert_exp = datetime.datetime.strptime(str(cert.get_notAfter().decode("utf-8")[:-1]), "%Y%m%d%H%M%S")
    exp_days = (cert_exp - datetime.datetime.utcnow()).days
    if (exp_days < 1):
        print("Certificate for " + str(host) + " ALREADY EXPIRED!\n")
        sys.stdout.flush()
    elif (exp_days < 31):
        print("Certificate for " + str(host) + " expiring within 1 month!")
        print("Days remaining: " + str(exp_days) + "\n")
        sys.stdout.flush()
    else:
        print("Certificate for " + str(host) + " good for " + str(exp_days) + " more days.\n")
        sys.stdout.flush()


# Create empty list for arguments
host_list = []

if args.hosts:
    for host in args.hosts:
        host_list.append(host)

if args.nets:
    for network in args.nets:
        for host in netaddr.IPNetwork(network).iter_hosts() :
            host_list.append(host)
#            print("Adding host: " + str(host))
    
for host in host_list:
    try :
        check_host_certificate(str(host))
    except ConnectionRefusedError: 
        print("Connection REFUSED\nMoving on...\n")
        sys.stdout.flush()
    except TimeoutError:
        print("Connection TIMEOUT\nMoving on...\n")
        sys.stdout.flush()
