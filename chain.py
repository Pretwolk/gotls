#!/usr/bin/env python3.4

import ssl
import smtplib
import pprint
import socket

#a = "srv.pretwolk.nl"
#a = "mail.v-dmeer.nl"
a = "smtp.gotls.info"
b = "v-dmeer.nl"

try:
  with smtplib.SMTP(host=a,port=25,timeout=5) as smtp:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs()
    smtp.starttls(context=context)
    print("NSA SECURE")
except ssl.CertificateError as err:
  print(err)
except ssl.SSLError as err:
  print(err)
#  ssl_sock = context.wrap_socket(smtp.sock, server_hostname=a)

#  asdf = context.get_ca_certs()
#  asdf2 = context.get_ca_certs(binary_form=True)

#  for i in asdf:
#    pprint.pprint(i)
