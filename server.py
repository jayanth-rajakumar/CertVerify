import time
import ssl
import socket
import types
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Util import asn1
from OpenSSL import crypto
from OpenSSL import SSL
import pickle
import requests
import OpenSSL
import json
import hashlib
import subprocess
import os


class Server(BaseHTTPRequestHandler):
  def do_HEAD(self):
    return

  def do_POST(self):
  	return


  def do_GET(self):
   # print(self.headers.get('crl-or-ocsp'))
    if(self.headers.get('crl-or-ocsp')=='crl' or self.headers.get('crl-or-ocsp')=='both'):
      [crl_status,json_response]=handle_crl(str(self.path)[1:])
      json_response=crl_buildjson(crl_status,json_response,str(self.path)[1:])
    
        
    elif(self.headers.get('crl-or-ocsp')=='ocsp'):
      [ocsp_status,json_response]=handle_ocsp(str(self.path)[1:])
      json_response=ocsp_buildjson(ocsp_status,json_response)
    
    if(self.headers.get('crl-or-ocsp')=='both'):
      [ocsp_status,json_response_]=handle_ocsp(str(self.path)[1:])
      json_response_=ocsp_buildjson(ocsp_status,json_response_)

      if(crl_status=='CRLPASS' and ocsp_status=='OCSPPASS'):
        json_response["validation_result"] = "CRL and OCSP Verification Passed"
        json_response["ocsp_validation_result"] = "OCSP Verification Passed"
      elif(crl_status=='CRLFAIL' or ocsp_status=='OCSPFAIL'):
        json_response["validation_result"] = "Certificate Revoked!"
        json_response["validation_result_short"] = "REV"
        json_response["ocsp_validation_result"] = json_response_["ocsp_validation_result"]
        json_response["result_color_hex"]="#9c200d"
      else:
        json_response["validation_result"] = "Could not verify both: <br>" + json_response["crl_validation_result"] + ". <br>" + json_response_["ocsp_validation_result"]
        json_response["validation_result_short"] = "ERR"
        json_response["ocsp_validation_result"] = json_response_["ocsp_validation_result"]
        json_response["result_color_hex"]="#FF4500"


    #print(self.headers.get('crl-or-ocsp'))
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(json.dumps(json_response).encode("UTF-8"))
    
    print(self.path)
    return

def ocsp_buildjson (ocsp_status,json_response):
  if(ocsp_status=="OCSPPASS"):
    json_response["validation_result"] = "OCSP Verification Passed"
    json_response["validation_result_short"] = "OK"
    json_response["crl_validation_result"] = ""
    json_response["ocsp_validation_result"] = "OCSP Verification Passed"
    json_response["result_color_hex"]="#176439"
  elif(ocsp_status=="OCSPFAIL"):
    json_response["validation_result"] = "OCSP Verification Failed"
    json_response["validation_result_short"] = "REV"
    json_response["crl_validation_result"] = ""
    json_response["ocsp_validation_result"] = "OCSP Verification Failed"
    json_response["result_color_hex"]="#9c200d"
  elif (ocsp_status=="OCSPUNKNOWN"):
    json_response["validation_result"] = "Could not contact OCSP Responder"
    json_response["validation_result_short"] = "ERR"
    json_response["crl_validation_result"] = ""
    json_response["ocsp_validation_result"] = "OCSP Verification Error"
    json_response["result_color_hex"]="#FF4500"
  return json_response

def crl_buildjson (crl_status,json_response,hostname):
  if (crl_status=='CRLPASS'):
    json_response["validation_result"] = "CRL Verification Passed"
    json_response["validation_result_short"] = "OK"
    json_response["crl_validation_result"] = "CRL Verification Passed"
    json_response["ocsp_validation_result"] = ""
    json_response["result_color_hex"]="#176439"
  elif (crl_status=='NOCRL'):
    [ocsp_status,json_response]=handle_ocsp(hostname)
    json_response=ocsp_buildjson(ocsp_status,json_response)
    #json_response["crl_validation_result"]="Certfificate does not have a CRL"
    #json_response["validation_result_short"] = "ERR"
  elif (crl_status=='CRLFAIL'):
    json_response["validation_result"] = "CRL - Certificate Revoked"
    json_response["validation_result_short"] = "REV"
    json_response["crl_validation_result"] = "CRL - Certificate Revoked"
    json_response["ocsp_validation_result"] = ""
    json_response["result_color_hex"]="#9c200d"
  return json_response

def handle_crl (hostname):

  ctx = ssl.create_default_context()
 
  s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
  s.connect((hostname,443))
  cert=s.getpeercert()
  
  organizationName=""
  issuer_name=""
  for t in cert['subject']:
    if(t[0][0]=='organizationName'):
      organizationName=t[0][1]
  
  for t in cert['issuer']:
    if(t[0][0]=='organizationName'):
      issuer_name=t[0][1]

  json_response= {
   # "result_color_hex" : result_color_hex,
    #"validation_result" : validation_result,
    "subject_organization" : organizationName,
    "issuer_common_name" : "Issuer",
    "issuer_organization": issuer_name,
    "message" : "",
    #"validation_result_short" : validation_result_short
  }
  cert_serial=str(cert['serialNumber']).encode("UTF-8")
  
  try:
    cdp_hash=hashlib.md5(cert['crlDistributionPoints'][0].encode()).hexdigest()
  except KeyError:
    return ['NOCRL',json_response]

  cdp_path=Path(os.path.join(os.path.dirname(__file__), 'cache/' + cdp_hash))
  revoked_bool=False

  
  if(cdp_path.is_file()==False):

    revoked_bool=load_crl_to_disk(cert,cdp_hash) 

  else:

    fin=open(os.path.join(os.path.dirname(__file__), 'cache/' + cdp_hash),"rb")
    rvk_list=pickle.load(fin)
    fin.close()

    asn1time_1=int(rvk_list[1])
    asn1time_2=int(datetime.utcnow().strftime('%y%m%d%H%M%SZ')[:-1])
    print (asn1time_1, asn1time_2)

    if(asn1time_1 <= asn1time_2):
      print("CRL expired. Redownload...")
      revoked_bool=load_crl_to_disk(cert,cdp_hash)
    else:
      if(cert_serial in rvk_list[0]):
        revoked_bool=True

 

  if(revoked_bool==False):
    return ['CRLPASS', json_response]
  else:
    return ['CRLFAIL',json_response]


def handle_ocsp (hostname):
  host_hash=str(hashlib.md5(hostname.encode()).hexdigest())
  resp_path=os.path.join(os.path.dirname(__file__), 'cache/resp_' + host_hash + '.der')

  if(Path(resp_path).is_file()):
    print('Found cached ocsp')
    fin=open(resp_path, "rb")
    ocsp_resp = x509.ocsp.load_der_ocsp_response(fin.read())
    fin.close()

    CurrentDateTime=datetime.utcnow()
    NextUpdate=ocsp_resp.next_update
    if(CurrentDateTime<NextUpdate):
      print('Not Expired')
      ctx = ssl.create_default_context()
 
      s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
      s.connect((hostname,443))
      cert=s.getpeercert()
      
      organizationName=""
      issuer_name=""
      for t in cert['subject']:
        if(t[0][0]=='organizationName'):
          organizationName=t[0][1]
      
      for t in cert['issuer']:
        if(t[0][0]=='organizationName'):
          issuer_name=t[0][1]

      json_response= {
      # "result_color_hex" : result_color_hex,
        #"validation_result" : validation_result,
        "subject_organization" : organizationName,
        "issuer_common_name" : "Issuer",
        "issuer_organization": issuer_name,
        "message" : "",
        #"validation_result_short" : validation_result_short
      }
      if(str(ocsp_resp.certificate_status)=="OCSPCertStatus.GOOD"):
        print(ocsp_resp.certificate_status)
        return ['OCSPPASS',json_response]
      elif(str(ocsp_resp.certificate_status)=="OCSPCertStatus.REVOKED"):
        return ['OCSPFAIL',json_response]
      else:
        return ['OCSPUNKNOWN',json_response]

  dst = (hostname.encode("UTF-8"), 443)
  ctx = SSL.Context(SSL.SSLv23_METHOD)
  s = socket.create_connection(dst)
  s = SSL.Connection(ctx, s)
  s.request_ocsp()
  s.set_connect_state()
  s.set_tlsext_host_name(dst[0])

  s.sendall('HEAD / HTTP/1.0\n\n'.encode("UTF-8"))
  s.recv(16)

  certs = s.get_peer_cert_chain()
  cert_arr=[]
  for _, cert in enumerate(certs):
      cxf=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
      cert_arr.append(cxf)

  cert = x509.load_pem_x509_certificate(cert_arr[0], default_backend())
  try:
    org_name=cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
  except:
    org_name=""
  try:
    issuer_name=cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
  except:
    issuer_name=""

  json_response= {
   # "result_color_hex" : result_color_hex,
    #"validation_result" : validation_result,
    "subject_organization" : org_name,
    "issuer_common_name" : "",
    "issuer_organization": issuer_name,
    "message" : "",
    #"validation_result_short" : validation_result_short
  }

  
  
  cert_path=os.path.join(os.path.dirname(__file__), 'cache/cert_' + host_hash + '.pem')
  issuers_path=os.path.join(os.path.dirname(__file__), 'cache/issuers_' + host_hash + '.pem')
  
  fout=open(cert_path,"wb")
  fout.write(cert_arr[0])
  fout.close()

  fout=open(issuers_path,"wb")
  for i in range(1,len(cert_arr)):
      fout.write(cert_arr[i])
  fout.close()

  authinfooid=x509.ObjectIdentifier("1.3.6.1.5.5.7.1.1")
  authinfoext=cert.extensions.get_extension_for_oid(authinfooid)

  ocspUrl=""
  for access_desc in authinfoext.value:
      if(access_desc.access_method._name=="OCSP"):
          ocspUrl=access_desc.access_location.value
          
  ocspDomain=ocspUrl[7:]
  slash_index=ocspDomain.find('/')
  if(slash_index != -1):
    ocspDomain=ocspDomain[0:slash_index]

  cmd_text="openssl ocsp -issuer " + issuers_path + " -cert " + cert_path +  " -text -url " + ocspUrl + " -noverify -no_signature_verify -no_cert_verify -respout " + resp_path + " -header \"HOST\" " + ocspDomain
  
  try:
    subprocess.check_output(cmd_text,shell=True)   
  except subprocess.CalledProcessError:
    os.remove(cert_path)
    os.remove(issuers_path)
    return ['OCSPUNKNOWN',json_response]



  fin=open(resp_path, "rb")
  ocsp_resp = x509.ocsp.load_der_ocsp_response(fin.read())
  fin.close()

  os.remove(cert_path)
  os.remove(issuers_path)
  #os.remove(resp_path)
  
  if(str(ocsp_resp.certificate_status)=="OCSPCertStatus.GOOD"):
    print(ocsp_resp.certificate_status)
    return ['OCSPPASS',json_response]
  elif(str(ocsp_resp.certificate_status)=="OCSPCertStatus.REVOKED"):
    return ['OCSPFAIL',json_response]
  else:
    return ['OCSPUNKNOWN',json_response]
  



def load_crl_to_disk (cert,cdp_hash):

  revoked_bool=False
  req=requests.get(cert['crlDistributionPoints'][0])
  crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, req.content)
  cert_serial=str(cert['serialNumber']).encode("UTF-8")

  crl_seq = asn1.DerSequence()
  crl_seq.decode(req.content)
  tbsCertList = asn1.DerSequence()
  tbsCertList.decode(crl_seq[0])
  nextUpdate = asn1.DerObject()

  if isinstance(tbsCertList[0], str): # CRL v1
    nextUpdate.decode(tbsCertList[3])
  else:
    if tbsCertList[0] > 1: raise ValueError("unsupported CRL profile version: %d" % tbsCertList[0])
    nextUpdate.decode(tbsCertList[4])

  revoked_objects = crl_object.get_revoked()
  
  rvk_set=set()
  for rvk in revoked_objects:
    if(rvk.get_serial()==cert_serial):
      print('Cert revoked')
      revoked_bool=True
    rvk_set.add(rvk.get_serial())
  
  pkl_list=[]
  pkl_list.append(rvk_set)
  pkl_list.append(nextUpdate.payload[:-1])
  

  fout=open(os.path.join(os.path.dirname(__file__), 'cache/' + cdp_hash),"wb+")
  pickle.dump(pkl_list,fout)
  fout.close()

  return revoked_bool

HOST_NAME = 'localhost'
PORT_NUMBER = 8000

if(not os.path.isdir(os.path.join(os.path.dirname(__file__) , 'cache/'))):
  os.mkdir(os.path.join(os.path.dirname(__file__) , 'cache/'))



httpd = HTTPServer((HOST_NAME, PORT_NUMBER), Server)
print(time.asctime(), "Server UP - %s:%s" % (HOST_NAME, PORT_NUMBER))
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()
print(time.asctime(), "Server DOWN - %s:%s" % (HOST_NAME, PORT_NUMBER))

