#!/usr/bin/python3.4
import os, sys, threading, subprocess, socket, logging
import time, pytz
from datetime import datetime
import smtplib, spf, dns.resolver, dns.reversename, ipaddress
import pprint, csv, json
import ssl, hashlib, base64, binascii
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import tempfile, nmap
#import heartbleed
#import tempfile, nmap, scanner.heartbleed
#import tempfile, nmap, proj.scanner.heartbleed
from .heartbleed import *

log = logging
logformat = "%(lineno)d - %(message)s"
log.basicConfig(format=logformat, level=log.DEBUG)

class ScanDomain():
  """ Represents a single or multiple domain's MTA security capabilities """
  #mail_servers = None
  lst_ciphers = None
  results = {}
  #smtp = None
  #tls_session = None
  global test_protocols
  test_protocols = {
    3: ssl.PROTOCOL_TLSv1,
    4: ssl.PROTOCOL_TLSv1_1,
    5: ssl.PROTOCOL_TLSv1_2,
    2: ssl.PROTOCOL_SSLv23,
    1: ssl.PROTOCOL_SSLv3
  }
  global protocols_map 
  protocols_map = {
    2: "SSLv23",
    1: "SSLv3",
    3: "TLSv1",
    4: "TLSv1.1",
    5: "TLSv1.2"
  }
  global map_protocols
  map_protocols = { 
    "SSLv23": 2,
    "SSLv3": 1,
    "TLSv1": 3,
    "TLSv1.1": 4,
    "TLSv1.2": 5
  }

  def __init__(self, domain, test_protocols=test_protocols):
    """ Start scan as one thread per domain limited to 20 parallel scans at the 
        same time """

    self.test_protocols = test_protocols
    
    # disabled as want to input a single domain per scan for gotlsweb
    #self.domains = domains
    #thread_pool = []
    #sema = threading.Semaphore(value=20)
    #for domain in self.domains:
    #  thread = threading.Thread(
    #    target=self.start_domain,args=(domain,))
    #  thread_pool.append(thread)
    #  sema.acquire(timeout=15)
    #  thread.start()
    #for thread in thread_pool:
    #  thread.join(timeout=50)
    #  sema.release()

    self.domain = domain
    self.start_domain(self.domain)
 
  def start_domain(self, domain):
    """ Query the MX records of a single domain and 
        connect to the MTA(s in parallel)
    """
    thread_pool = []
    try:
      # get domain A and AAAA records
      mx_rdata = dns.resolver.query(domain, "MX")
    except:
      log.debug(domain)
      self.results[domain] = "NXDOMAIN"
      sys.exit()

    if domain not in self.results:
      self.results[domain] = {}
    addresses = []

    for rdata in mx_rdata:
      mx = rdata.exchange
      thread = threading.Thread(
        target=self.get_ip_addresses,args=(domain,mx,))
      thread_pool.append(thread)
      thread.start()
    for thread in thread_pool:
      thread.join(timeout=10) # waiting 10 seconds for a dns response

    address_list = []
    for addr,value in self.results[domain].items():
      if self.get_ip_version(addr):
        # if the same IP address is found in two MX records skip it
        if self.results[domain][addr]["SupportsTLS"] is None:
          address_list.append(addr)

    for addr in address_list:
      """
      COMMENCE DATA GATHERING
      """
      thread  = threading.Thread(
                target=self.detect_tls_characteristics,
                args=(domain,addr,))
      thread_pool.append(thread)
      thread.start()
    for thread in thread_pool:
      thread.join(timeout=60)

  def check_heartbleed(self, domain, address):
    """ Only check for hearbleed bug CVE-2014-0160 if TLS is on """
    if self.get_ip_version(address) == 4:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif self.get_ip_version(address) == 6:
      s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
      return False
    log.debug( 'Connecting...')
    sys.stdout.flush()
    try:
      s.connect((address, 25))

      # Execute STARTTLS
      re = s.recv(4096)
      #if opts.debug: print( re)
      s.send(b'ehlo ' + str.encode(domain) + b'\n')
      re = s.recv(1024)
      s.send(b'starttls\n')
      re = s.recv(1024)

      # TLS handshake (Client/Server Hellos)
      log.debug( 'Sending Client Hello...')
      sys.stdout.flush()
      s.send(heartbleed.hello)
      log.debug( 'Waiting for Server Hello...')
      #sys.stdout.flush()
      while True:
          typ, ver, pay = heartbleed.recvmsg(s)
          if typ == None:
              logging.debug('Server closed connection without\
                            sending Server Hello.')
              return False
          # Look for server hello done message.
          if typ == 22 and pay[0] == 0x0E:
              break

      # Exploit Heartbleed
      log.debug( 'Sending heartbeat request...')
      s.send(heartbleed.hb)
      heart = heartbleed.hit_hb(s)
      if heart == True:
        self.add_to_result(domain,address,"Heartbleed", True)
        log.debug('Heartbleed effected')
      elif heart == False:
        self.add_to_result(domain,address,"Heartbleed", False)
        log.debug('Heartbleed no effected')
      s.send(b'quit\n')
    except:
      self.add_to_result(domain,address,"Heartbleed", False)
      log.debug('Check got interrupted assuming not Heartbleed effected')
      return False

  def check_vulnkey(self, cert):
    """ uses openssl-vulnkey """
    temp_file = tempfile.NamedTemporaryFile()
    temp_file.write(cert)
    temp_file.read()
    call = subprocess.check_output(["openssl-vulnkey", temp_file.name])
    if b'Not blacklisted' in call:
      return False
    elif b'COMPROMISED' in call:
      #log.debug('This key is blacklisted:\n%s', call)
      return True
    temp_file.close()

  def get_cert_moduli(self, derCert):
    # convert PEM to DER
    pem = derCert.decode()
    lines = pem.replace(" ",'').split()
    der = binascii.a2b_base64(''.join(lines[1:-1]))

    # get Subject Public Key
    cert = DerSequence()
    b = cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    try:
      subjectPublicKeyInfo = tbsCertificate[6]
    except IndexError:
      return "unkown", "unkown"

    rsa_key = RSA.importKey(subjectPublicKeyInfo)
    # rsa_key.n = modulus, rsa_key.e = public exponent
    # increment size with 1 as the Python counts from 0 (duh)
    return (hex(rsa_key.n), rsa_key.key.size() + 1)

  def parse_results(self):
    self.load_result()

    html = []
    html.append("<table border='1'>")
    html.append("<thead><tr>")
    html.append("<th colspan='3'>MX records / PTR record / IP addresses:</th>")
    html.append("<th colspan='1'>Serverstate:</th>")
    html.append("<th colspan='1'>Product:</th>")
    html.append("<th colspan='3'>TLS / Protocols / Ciphers:</th>")
    html.append("</tr></thead>")
    for domain, domainvalues in self.results.items():
      html.append("<tr class='domain'>")
      html.append("<td colspan='12'><a id="+domain+">"+domain+" ("+ 
                  str(len(domainvalues)-1)+")</td>")
      html.append("</tr>")

      for address, addressvalues in domainvalues.items():
        version = self.get_ip_version(address)
        if version:
          html.append("<tr class='server'>")
          html.append("<td>" + "<br />".join(addressvalues["mx"])+"</td>")
          html.append("<td>" + str(addressvalues["PTR"])+"</td>")
          html.append("<td>IPv"+str(version)+": "+address+"</td>")
          html.append("<td>"+str(addressvalues["ServerState"])+"</td>")
          html.append("<td>"+str(addressvalues["Product"])+"</td>")
          html.append("<td>"+str(addressvalues["SupportsTLS"])+"</td>")
          if "SupportedTLSProtocols" in addressvalues:
            html.append("<td>" + "<br />".join(
                          addressvalues["SupportedTLSProtocols"]
                          )+"</td>")
          html.append("</tr>")
          
    html.append("</table>")

    flathtml = "\n".join(html)

    with open("/opt/gotls/results.html","w") as fh:
      fh.write(flathtml)
      fh.write("<pre>" + str(self.results) + "</pre>")
      fh.close

  def detect_tls_characteristics(self,domain,addr):

    log.debug(addr + " - Getting PTR record")
    self.get_ptr(domain,addr)

    log.debug(addr + " - Detecting server state")
    self.get_server_state(domain,addr)

    log.debug(addr + " - Resolving SPF records")
    self.check_spf(domain,addr)

    if self.results[domain][addr]["ServerState"]:

      log.debug(addr + " - Detecting TLS")
      self.results[domain][addr]["RateLimited"] = False
      self.tls_detect(domain,addr)

      log.debug(addr + " has TLS: "
                + str(self.results[domain][addr]["SupportsTLS"]))

      if self.results[domain][addr]["SupportsTLS"] == True:
        log.debug(addr + " - Getting peer certificate for")
        self.get_peer_certificate(domain,addr)

        log.debug(addr + " - Detecting SSL/TLS protocols for")
        self.tls_protocol_detection(domain,addr)

        log.debug(addr + " - Verifing peer cert chain for")
        self.tls_verify_cert_chain(domain,addr)

        log.debug(addr + " - Detecting ciphers available for")
        self.tls_cipher_list(domain,addr)

        log.debug(addr + " - Checking for heartbleed on")
        self.check_heartbleed(domain,addr)
        log.debug(addr + " - \t\t Done checking for heartbleed on")

#        log.debug("Verifing certificate hostname")
#        self.match_certificate_hostname(domain,addr)

#        log.debug("Verifing certificate if valid in time")
#        self.verify_time(domain,addr)
  
      else:
        #log.debug(domain + " " + addr + " has no TLS support")
        pass
    else:
        #log.debug(domain + " " + addr + " is DOWN")
        pass

  def check_spf(self,domain,addr):

    if "_spf" not in self.results[domain]:
      self.results[domain]["_spf"] = {}

    mxs = self.results[domain][addr]["mx"]

    for mx in mxs:
      if mx not in self.results[domain]["_spf"]:
        asd = spf.check(i=addr,
                        s=domain,
                        h=mx)
        self.results[domain]["_spf"][mx] = asd[0]
      
  def get_ip_addresses(self, domain, server):
    """Given a MX record, return its IP addresses"""
    # get v4
    try:
      ipv4 = dns.resolver.query(server, "A")
      ipv4list = []
      for x in ipv4:
        ipv4list.append(str(x.address))

        if x.address not in self.results[domain]:
          self.results[domain][x.address] = {}
          self.results[domain][x.address]["mx"] = []
          if "SupportsTLS" in self.results[domain][x.address]:
            log.debug("RESETTING TLS FOR " + x.address)
          self.results[domain][x.address]["SupportsTLS"] = None
  
        if str(server) not in self.results[domain][x.address]["mx"]:
          self.results[domain][x.address]["mx"].append(str(server))

    except dns.resolver.NXDOMAIN:
      ipv4list = []
    except dns.resolver.NoAnswer:
      ipv4list = []
    # get v6
    try:
      ipv6 = dns.resolver.query(server, "AAAA")
      ipv6list = []
      for x in ipv6:
        ipv6list.append(str(x.address))

        if x.address not in self.results[domain]:
          self.results[domain][x.address] = {}
          self.results[domain][x.address]["mx"] = []
          if "SupportsTLS" in self.results[domain][x.address]:
            log.debug("RESETTING TLS FOR " + x.address)
          self.results[domain][x.address]["SupportsTLS"] = None

        if str(server) not in self.results[domain][x.address]["mx"]:
          self.results[domain][x.address]["mx"].append(str(server))
    except dns.resolver.NXDOMAIN:
      ipv6list = []
    except dns.resolver.NoAnswer:
      ipv6list = [] 
    # return v4 and v6
    return ipv4list + ipv6list  

  def store_results(self):
    #pickle.dump(self.results,open("results","wb"),protocol=4)
    with open('data.txt', 'w') as outfile:
      json.dump(self.results, outfile)
    #pprint.pprint(self.results)

  def get_results(self):
    """ for web application """
    #return json.dumps(self.results, sort_keys=True, indent=4)
    return self.results

  def load_result(self):
    self.results = pickle.load(open("results","rb"))

  def verify_time(self, domain, addr):
    try: 
      hash = self.results[domain][addr]["cert"]
      objCert = self.results["_certs"][hash]["object"]

      local = pytz.timezone ("UTC")
      notBefore = local.localize(datetime.strptime(notBefore,
        "%b %d %H:%M:%S %Y %Z"),is_dst=None).astimezone(pytz.utc)
      notAfter  = local.localize(datetime.strptime(notAfter,
        "%b %d %H:%M:%S %Y %Z"),is_dst=None).astimezone(pytz.utc)
      now       = local.localize(datetime.utcnow()).astimezone(pytz.utc)

      if now < notBefore:
        return (False,"Certificate not yet valid")
      elif now > notAfter:
        return (False,"Certificate expired")
      else:
        return (True,"Certificate is valid in time!")

    except:
      return (False,"No certificate found")

  def add_to_result(self, server, address, key, value):
    self.results[server][address][key] = value

  def add_cert(self,server,address,objCert,derCert,objChain,derChain):
    derCert_utf8 = derCert.encode("UTF-8")
    shasum = hashlib.sha512(derCert_utf8).hexdigest()
    self.add_to_result(server,address,"cert",shasum)
    moduli, keysize = self.get_cert_moduli(derCert_utf8)
    vulnerablekey = self.check_vulnkey(derCert_utf8)


    if "_certs" not in self.results[server]:
      self.results[server]["_certs"] = {}

    if shasum not in self.results[server]["_certs"]:
      self.results[server]["_certs"][shasum] = {}

      self.results[server]["_certs"][shasum]["object"] = objCert
      self.results[server]["_certs"][shasum]["der"] = derCert
      self.results[server]["_certs"][shasum]["objChain"] = objChain
      # convert the list of byte str to unicode str 
      # for JSON compatibility (using List Comprehensions)
      try:
        derChain_unicode = \
          [i.decode('UTF-8') if isinstance(i, unicode) else i for i in derChain]
        self.results[server]["_certs"][shasum]["derChain"] = derChain_unicode
      except NameError:
        # in case no cert is found make it an empty string
        self.results[server]["_certs"][shasum]["derChain"] = ""
      self.results[server]["_certs"][shasum]["moduli"] = moduli
      self.results[server]["_certs"][shasum]["keysize"] = keysize
      self.results[server]["_certs"][shasum]["vulnerablekey"] = vulnerablekey

  def get_server_state(self, server, address, port = "25"):
    address = str(address)
    port    = str(port)

    try: 
      nm = nmap.PortScanner()

      if self.get_ip_version(address) == 4:
        nm.scan(
          address,
          arguments='-Pn --host-timeout=250ms --max_rtt_timeout=2s -p' + port
        )
      elif self.get_ip_version(address) == 6:
        nm.scan(
          address,
          arguments='-Pn -6 --host-timeout=250ms --max_rtt_timeout=2s -p' + port
        )

      product = nm[address]['tcp'][int(port)]['product'].strip()
      state   = nm[address]['tcp'][int(port)]['state'].strip()
      reason   = nm[address]['tcp'][int(port)]['reason'].strip()
      
      if state == "open":
        self.add_to_result(server,address,"ServerState",True)
      else:
        self.add_to_result(server,address,"ServerState",False)

      self.add_to_result(server,address,"NmapState",(state,reason))
      self.add_to_result(server,address,"Product",product)
      return True

    except:
      self.add_to_result(server,address,"ServerState",False);
      return False

  def get_ptr(self,server,address):
    try:
      n = dns.reversename.from_address(address)
      ptr = dns.resolver.query(n, 'PTR').rrset.items[0]
      self.add_to_result(server,address,"PTR",str(ptr))
      return True

    except:
      self.add_to_result(
          server,
          address,
          "PTR",False)
      return False

  def get_ip_version(self, address):
    try:
      if 4 == ipaddress.IPv4Address(address).version:
        return int(4)
    except:
      pass

    try:
      if 6 == ipaddress.IPv6Address(address).version:
        return int(6)
    except: 
      pass

    return False

  def match_certificate_hostname(self, domain, addr): 

    if self.results[domain][addr]["SupportsTLS"]:
      certhash = self.results[domain][addr]["cert"]
      cert = self.results[domain]["_certs"][certhash]["object"]

      try:    
        matches = {}

        for mx in self.results[domain][addr]["mx"]:
          if mx[-1:] == ".":
            mx = mx[:-1]
        
          if ssl.match_hostname(cert,mx) == None:
            matches[mx] = (True,certhash,mx)
        
        self.add_to_result(domain,addr,"CertificateValid",matches)
        return True

      except:
        self.add_to_result(domain,addr,"CertificateValid",False)
        return False

  def get_cipher_list(self):

    if self.lst_ciphers == None:
      cipher_list = subprocess.check_output(
            ["/usr/bin/openssl","ciphers","-v"],
            universal_newlines=True).split("\n")

      ciphers= []

      t = 0;
      for cipher_line in cipher_list:
        cipher_line = cipher_line.split("\t")

        if t > 30:
          break

        for cipher_props in cipher_line:
          list = [ x for x in cipher_props.split(" ") if x ]
          if len(list) > 2:
            if (list[0],list[1]) not in ciphers:
              ciphers.append((list[0],list[1]))
        t += 1

      self.lst_ciphers = ciphers
    return self.lst_ciphers

  def tls_cipher_list(self, domain, address):
    if "SupportedCiphers" not in self.results[domain][address]:
      self.results[domain][address]["SupportedCiphers"] = []

    cipher_list = self.get_cipher_list()
    for cipher in cipher_list:
      tls = self.initiate_smtp(domain,
        address,
        cipher = cipher[0],
        close = True)

      if (tls[0] == True
        and cipher[0] 
        not in self.results[domain][address]["SupportedCiphers"]):
        self.results[domain][address]["SupportedCiphers"].append(cipher[0])

    return True

  def tls_detect(self,domain,address):

    if not self.results[domain][address]["ServerState"]:
      return ((False,"Server Down"))
    try:
      with smtplib.SMTP(host=address,port=25,timeout=5) as smtp:
        context = ssl.SSLContext(test_protocols[3])
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
        context.load_default_certs()
        smtp.ehlo(name=domain)
        if not smtp.has_extn("STARTTLS"):
          self.add_to_result(domain,address,"SupportsTLS",False)
          log.debug("%s does not have STARTTLS", address)
          smtp.close()
          return ((False,"No STARTTLS support"))
        else:
          try:
            smtp.starttls(context=context)
            self.add_to_result(domain,address,"SupportsTLS",True)
          except:
            self.add_to_result(domain,address,"SupportsTLS",False)
            return ((False,"STARTTLS could not be initialized"))
        smtp.close()
        return ((True,"Stupid placeholder"))

    except ConnectionRefusedError:
      self.add_to_result(domain,address,"SupportsTLS",False)
      self.add_to_result(domain,address,"RateLimited",True)
      return ((False,domain + " " + address + "SMTP connection is ratelimited"))
    except smtplib.SMTPConnectError as error:
      # error.smtp_code could be used in the future for debugging
      self.add_to_result(domain,address,"SupportsTLS",False)
      self.add_to_result(domain,address,"RateLimited",True)
      return ((False,domain + " " + address + "SMTP connection is ratelimited"))
    except:
      log.debug(domain + " " + address + " SMTP connection failed")
      return ((False,domain + " " + address + " SMTP connection failed"))

  def initiate_smtp(self,
                    domain,
                    address,
                    sslproto = int(3),
                    sslreqs = ssl.CERT_NONE, 
                    cipher = False,
                    close = False):

    if not self.results[domain][address]["ServerState"]:
      return ((False,"Server Down"))
    try:
      if not self.results[domain][address]["RateLimited"]:
        with smtplib.SMTP(host=address,port=25,timeout=5) as smtp:
          context = ssl.SSLContext(test_protocols[sslproto])
          context.verify_mode = sslreqs
          context.check_hostname = False
          context.load_default_certs()
          if cipher:
            context.set_ciphers(cipher)
          smtp.ehlo(name=domain)
          if not smtp.has_extn("STARTTLS"):
            smtp.close()
            return ((False,"No STARTTLS support"))
          else:
            try:
              smtp.starttls(context=context)
            except:
              return ((False,"STARTTLS could not be initialized"))
          if close:
            smtp.close()
            return ((True,"Stupid placeholder"))
          else:
            return ((True,smtp,context))

    except ConnectionRefusedError:
      self.add_to_result(domain,address,"RateLimited",True)
      return ((False,domain + " " + address + "SMTP connection is ratelimited"))
    except smtplib.SMTPConnectError as error:
      # error.smtp_code could be used in the future for debugging
      self.add_to_result(domain,address,"RateLimited",True)
      return ((False,domain + " " + address + "SMTP connection is ratelimited"))
    except:
      log.debug(domain + " " + address + " SMTP connection failed")
      return ((False,domain + " " + address + " SMTP connection failed"))

  def get_peer_certificate(self,domain,address):
    if not self.results[domain][address]["RateLimited"]:
      try:
        with smtplib.SMTP(host=address,port=25,timeout=5) as smtp:
          smtp.ehlo(name=domain)
          smtp.docmd("STARTTLS")

          tls_session = ssl.wrap_socket(
                          smtp.sock,
                          cert_reqs=ssl.CERT_NONE,
                          ca_certs="/etc/ssl/certs/ca-certificates.crt")

          objCert = tls_session.getpeercert()
          derCert = ssl.DER_cert_to_PEM_cert(
            tls_session.getpeercert(binary_form=True))
          smtp.close()
      except ConnectionRefusedError:
        self.add_to_result(domain,address,"RateLimited",True)
        return ((
                False, 
                domain + " " + address + "SMTP connection is ratelimited"
               ))
      except smtplib.SMTPConnectError as error:
        # error.smtp_code could be used in the future for debugging
        self.add_to_result(domain,address,"RateLimited",True)
        return ((
                False,
                domain + " " + address + "SMTP connection is ratelimited"
               ))
      except:
        log.debug(domain + " " + address + " SMTP connection failed")
        return ((False,domain + " " + address + " SMTP connection failed"))

      context = self.initiate_smtp(domain,address)
      if context[0] and not self.results[domain][address]["RateLimited"]:
        smtp = context[1]
        context = context[2]

        objChain = context.get_ca_certs()
        derChain = context.get_ca_certs(binary_form=True)
      else:
        objChain = None
        derChain = None

      self.add_cert(domain,address,objCert,derCert,objChain,derChain)

      smtp.close()

  def tls_verify_cert_chain(self,domain,addr):
    mxs = self.results[domain][addr]["mx"]

    if "VerifiedChain" not in self.results[domain][addr]:
      self.results[domain][addr]["VerifiedChain"] = {}

    for mx in mxs:
      mx = mx[:-1] #Remove trailing dot root
      if mx not in self.results[domain][addr]["VerifiedChain"]:
        self.results[domain][addr]["VerifiedChain"][mx] = None

        protolist = []
        for proto in self.results[domain][addr]["SupportedTLSProtocols"]:
          protolist.append(map_protocols[proto])
        proto = max(protolist)

        try:
          if not self.results[domain][addr]["RateLimited"]:
            with smtplib.SMTP(host=mx,port=25,timeout=5) as smtp:
              smtp.ehlo(domain)

              context = ssl.SSLContext(test_protocols[proto])
              context.verify_mode = ssl.CERT_REQUIRED 
        
              #Uncommented, does not work yet 
              #context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
              context.check_hostname = True
              context.load_default_certs()
              context.set_default_verify_paths()
              context.load_verify_locations(capath="/etc/ssl/certs")
              smtp.starttls(context=context)
              #log.debug("Certificate VALID")
              smtp.close()
              self.results[domain][addr]["VerifiedChain"][mx] = (True, "Valid")
              log.debug(
                "CONNECTED WITH: " + addr + " and " + protocols_map[proto]
              )
        except ssl.CertificateError as err: 
          log.debug(err)
          self.results[domain][addr]["VerifiedChain"][mx] = (False, str(err))
        except ssl.SSLError as err: 
          log.debug(err)
          self.results[domain][addr]["VerifiedChain"][mx] = (False, str(err))
        except ConnectionRefusedError as err:
          log.debug(err)
          self.add_to_result(domain,addr,"RateLimited",True)
          log.debug(domain + " " + addr + "SMTP connection is ratelimited")
          return ((
                   False,
                   domain + " " + addr + "SMTP connection is ratelimited"
                  ))
        except smtplib.SMTPConnectError as error:
          log.debug(error)
          # error.smtp_code could be used in the future for debugging
          self.add_to_result(domain,addr,"RateLimited",True)
          return ((
                   False,
                   domain + " " + addr +  " " 
                   + "SMTP connection is ratelimited"
                 ))
        except Exception as error:
          log.debug(
                    domain + " " + addr + " "
                    + "SMTP connection failed, exception:\n"
                    + error
                   )
          self.results[domain][addr]["VerifiedChain"][mx] = \
            (
             False,
             domain + " " + addr + "an Exception in def tls_verify_cert_chain"
            )
          return ((False,domain + " " + addr + " SMTP connection failed"))

        #except smtplib.SMTPConnectError as error:
        #  self.results[domain][address]["RateLimited"] = True
        #except Exception as err:
        #  log.debug(addr + " - " + str(err))
        #  self.results[domain][addr]["VerifiedChain"][mx] = (False, str(err))

  def tls_protocol_detection(self, domain, address):
    self.results[domain][address]["SupportedTLSProtocols"] = []

    for ssl_proto in self.test_protocols:
      session = self.initiate_smtp(domain, address, ssl_proto)
      if session[0]:
        session[1].close()
        results_tlsv = self.results[domain][address]["SupportedTLSProtocols"]
        if protocols_map[ssl_proto] not in results_tlsv:
          self.results[domain][address]["SupportedTLSProtocols"].append(
            protocols_map[ssl_proto]
          )

""""""""""""""""""
"""END OF CLASS"""
""""""""""""""""""

#test_protocols = {
#  3: ssl.PROTOCOL_TLSv1,
#  4: ssl.PROTOCOL_TLSv1_1,
#  5: ssl.PROTOCOL_TLSv1_2,
#  2: ssl.PROTOCOL_SSLv23,
#  1: ssl.PROTOCOL_SSLv3
#}
#
#protocols_map = {
#  2: "SSLv23",
#  1: "SSLv3",
#  3: "TLSv1",
#  4: "TLSv1.1",
#  5: "TLSv1.2"
#}
#
#map_protocols = { 
#  "SSLv23": 2,
#  "SSLv3": 1,
#  "TLSv1": 3,
#  "TLSv1.1": 4,
#  "TLSv1.2": 5
#}


if __name__ == "__main__":
  # get domain from stdin
  if len(sys.argv)>1:
    domain_name = sys.argv[1:]
  # get domain(s) from a csv fiel
  else:
    with open('attack_list.csv',newline='') as attack_list:
      attack_list = csv.reader(attack_list, delimiter=',')
      for name in attack_list:
        if len(domain[1].strip()) > 0:
          domain_name.append(domain[1].strip())
  
  target = ScanDomain(domain_name,test_protocols)
  # save to a JSON file
  print(target.get_results())
  
# vim: tabstop=4 expandtab shiftwidth=2 softtabstop=2
