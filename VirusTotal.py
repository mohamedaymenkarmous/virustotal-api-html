#!/usr/bin/python3
from __future__ import print_function
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from json2html import *
import imgkit
import hashlib
import mysql.connector
import time
import os

INPUT_TYPE_ARGUMENT="Argument"
INPUT_TYPE_FILE="File"
PERSISTENCE_TYPE_SQL="SQL"
PERSISTENCE_TYPE_NONE="None"

class VirusTotal:
  OutputDir = None
  HTMLHeader = None
  APIKeys = None
  APIKEY = None
  APIKeysNumber = None
  APIKeyIndex = None
  DisabledAttr = None
  MaxResults = None
  AttrSubstitution = None
  Order = None
  VTInstance = None
  Persistence = None
  Host = None
  Database = None
  UsernameR = None
  PasswordR = None
  UsernameRW = None
  PasswordRW = None
  Input = None
  IP = None
  GeneralOutput = None
  DBR = None
  DBRW = None
  CursorR = None
  CursorRW = None

  def init(self):
    config=None
    try:
      with open('config.json', 'r') as configFile:
        configContent = configFile.read()
        config=json.loads(configContent)
    except json.decoder.JSONDecodeError:
      print("Problem occured while parsing the config.json file")
      exit()
    if config==None:
      print("Problem occured while parsing the config.json file")
      exit()
    self.OutputDir = config['General']['OutputDir']
    self.HTMLHeader = config['General']['HTMLHeader']
    self.TablesClass = config['General']['TablesClass']
    self.APIKeys = config['VirusTotal']['APIKeys']
    self.loadRecordsTmp()
    self.APIKEY = self.APIKeys[self.APIKeyIndex]
    self.APIKeysNumber = len(self.APIKeys)
    self.DisabledAttr = config['VirusTotal']['DisabledAttr']
    self.MaxResults = config['VirusTotal']['MaxResults']
    self.AttrSubstitution = config['VirusTotal']['AttrSubstitution']
    self.Order = config['VirusTotal']['Order']
    self.VTInstance = VirusTotalPublicApi(self.APIKEY)
    self.Persistence = config['VirusTotal']['Persistence']
    self.Host = config['VirusTotal']['PersistenceCredentials']['host']
    self.Database = config['VirusTotal']['PersistenceCredentials']['database']
    self.UsernameR = config['VirusTotal']['PersistenceCredentials']['username_r']
    self.PasswordR = config['VirusTotal']['PersistenceCredentials']['password_r']
    self.UsernameRW = config['VirusTotal']['PersistenceCredentials']['username_rw']
    self.PasswordRW = config['VirusTotal']['PersistenceCredentials']['password_rw']
    self.Input = config['VirusTotal']['Input']
    self.GeneralOutput = config['VirusTotal']['GeneralOutput']
    self.HTML=""
    self.IMG=""
    if self.Persistence==PERSISTENCE_TYPE_SQL:
      self.initSQL()

  def initSQL(self):
    self.DBR = mysql.connector.connect(
      host=self.Host,
      user=self.UsernameR,
      passwd=self.PasswordR,
      database=self.Database
    )
    self.CursorR = self.DBR.cursor(dictionary=True)
    self.DBRW = mysql.connector.connect(
      host=self.Host,
      user=self.UsernameRW,
      passwd=self.PasswordRW,
      database=self.Database
    )
    self.CursorRW = self.DBRW.cursor(dictionary=True)

  def resetSQL(self):
    self.CursorR.close()
    self.CursorRW.close()
    self.DBR.close()
    self.DBRW.close()
    self.initSQL()

  def preHandling(self):
    self.number={}
    self.history={}

  def loadRecordsTmp(self):
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
        self.APIKeyIndex=recordsTmp["APIKeyIndex"]
    except Exception:
      self.APIKeyIndex=0
      recordsTmp={"APIKeyIndex":self.APIKeyIndex}
      with open('.records.tmp', 'w') as recordsTmpFile:
        json.dump(recordsTmp, recordsTmpFile)

  def updateAPIKeyIndex(self):
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
    except Exception:
      recordsTmp={"APIKeyIndex":self.APIKeyIndex}
    recordsTmp["APIKeyIndex"]=self.APIKeyIndex
    with open('.records.tmp', 'w') as recordsTmpFile:
      json.dump(recordsTmp, recordsTmpFile)

  def updateVTInstance(self):
    self.APIKeyIndex=(self.APIKeyIndex+1)%self.APIKeysNumber
    self.updateAPIKeyIndex()
    self.APIKEY = self.APIKeys[self.APIKeyIndex]
    self.VTInstance = VirusTotalPublicApi(self.APIKEY)

  def getIPReportAPI(self):
    if self.Input==INPUT_TYPE_FILE:
      return self.getIPReportAPIFile()
    elif self.Input==INPUT_TYPE_ARGUMENT:
      return self.getIPReportAPIArgument()
    return {}

  def getIPReportAPIArgument(self):
    ips="\n".join(self.IP.split(" ")).strip()
    return self.getVTReport(ips)

  def getIPReportAPIFile(self):
    result={}
    with open("input_ip.txt") as file:
      ips=file.read().strip()
      result=self.getVTReport(ips)
    return result

  def getVTReport(self,ips):
    result={}
    for ip in ips.split("\n"):
      response = self.VTInstance.get_ip_report(ip)
      self.updateVTInstance()
      if response['response_code']==200:
        result[ip]=response['results']
    return result

  def setHTMLDomain(self,domain):
    return '<a href="https://www.virustotal.com/gui/domain/'+domain+'/details">'+domain+'</a>'

  def formatArrayDateDomain(self,ip_report_api,attr):
      result=[]
      count=self.MaxResults[attr] if self.MaxResults[attr] else -1
      tmp=sorted(ip_report_api[attr], key=lambda i: i['last_resolved'])
      for elem in list(reversed(tmp)):
        if count==0:
          break
        obj={'Date resolved':"", 'Domain':""}
        obj['Date resolved']=elem['last_resolved']
        obj['Domain']=self.setHTMLDomain(elem['hostname'])
        result.append(obj)
        count=count-1
      return result

  def setHTMLFileHash(self,hash):
    return '<a href="https://www.virustotal.com/gui/file/'+hash+'/detection">'+hash+'</a>'

  def formatArrayDateScoreHash(self,ip_report_api,attr):
      result=[]
      count=self.MaxResults[attr] if self.MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'File Hash (sha256)':""}
        obj['Scanned']=elem['date']
        if elem['positives']==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem['positives'])+"</span>/"+str(elem['total'])
        #response=self.VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['File Hash (sha256)']=self.setHTMLFileHash(elem['sha256'])
        result.append(obj)
        count=count-1
      return result

  def setHTMLURL(self,url,url_hash):
    if url_hash==False:
      url_hash=hashlib.sha256(url.encode('utf-8')).hexdigest()
    return '<a href="https://www.virustotal.com/gui/url/'+url_hash+'/detection">'+url+'</a>'

  def formatArrayDateScoreURL(self,ip_report_api,attr):
      result=[]
      count=self.MaxResults[attr] if self.MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'URL':""}
        obj['Scanned']=elem['scan_date']
        if elem['positives']==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem['positives'])+"</span>/"+str(elem['total'])
        #response=self.VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['URL']=self.setHTMLURL(elem['url'],False)
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateScoreURLnum(self,ip_report_api,attr):
      result=[]
      count=self.MaxResults[attr] if self.MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'URL':""}
        obj['Scanned']=elem[4]
        if elem[2]==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem[2])+"</span>/"+str(elem[3])
        #response=self.VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['URL']=self.setHTMLURL(elem[0],elem[1])
        result.append(obj)
        count=count-1
      return result

  def getNumberMalicious(self,ip_report_api,attr):
      result=[d for d in ip_report_api[attr] if ('positives' in d and d['positives']>0) or ('positives' not in d and d[2]>0)]
      return result

  def getNumberBenign(self,ip_report_api,attr):
      result=[d for d in ip_report_api[attr] if ('positives' in d and d['positives']==0) or ('positives' not in d and d[2]==0)]
      return result

  def updateScoredAttr(self,attr,verdict,result):
      self.number[attr]=self.number[attr] if attr in self.number else {}
      self.number[attr][verdict]=result

  def getIPReportFiltered(self,ip_report_api):
      result={}
      for attr in list(ip_report_api):
        if(attr in self.DisabledAttr):
          None #del result[attr]
        elif attr=='resolutions':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          self.history[newAttr]=len(ip_report_api[attr])
          result[newAttr]=self.formatArrayDateDomain(ip_report_api,attr)
        elif attr=='detected_referrer_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_referrer_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_downloaded_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_downloaded_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_communicating_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_communicating_samples':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_urls':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreURL(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_urls':
          newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
          tmp=self.formatArrayDateScoreURLnum(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        else:
          result[attr]=ip_report_api[attr]
      return result

  def getOrdered(self,ip_report_filtered):
      result={}
      #We order the Order's elements in the begining of the result list
      for elem in self.Order:
        #If the substitued element index exists in the Order list, then it should be ordered
        if elem in self.AttrSubstitution and self.AttrSubstitution[elem] and self.AttrSubstitution[elem] in ip_report_filtered and ip_report_filtered[self.AttrSubstitution[elem]]:
          #Ordered elements should not duplicated
          if self.AttrSubstitution[elem] not in result:
            result[self.AttrSubstitution[elem]]=ip_report_filtered[self.AttrSubstitution[elem]]
        #If the index is not substitutable and if the index exists in the Order list, then it should be ordered
        elif elem in ip_report_filtered and ip_report_filtered[elem]:
          #Ordered elements should not duplicated
          if elem not in result:
            result[elem]=ip_report_filtered[elem]
      #Then, we add the non ordered elements since they are not blacklisted so of the Order list is missing some elements, they will be added in the end of the result list
      for attr in list(ip_report_filtered):
        #Ordered elements should not duplicated
        if attr not in result:
          result[attr]=ip_report_filtered[attr]
      return result

  def getHTML(self,ip_report_filtered,ip):
      html=""
      html=html+"<h3>IP Address: "+ip+"</h3>"
      for elem in list(ip_report_filtered):
        html=html+"<h4>"+elem+"</h4>"
        if elem in self.number and self.number[elem]:
          malicious=self.number[elem]["malicious"] if "malicious" in self.number[elem] else 0
          benign=self.number[elem]["benign"] if "benign" in self.number[elem] else 0
          html=html+"<h5>(<span style='color:red'>"+str(malicious)+" malicious</span> and <span style='color:green'>"+str(benign)+" benign</span>)</h5>"
        if elem in self.history and self.history[elem]:
          history=self.history[elem]
          html=html+"<h5>("+str(history)+" found)</h5>"
        html=html+json2html.convert(json = ip_report_filtered[elem], table_attributes='class="'+self.TablesClass+'"',escape=False)
      self.HTML=self.HTML+html
      html='<html><head>'+self.HTMLHeader+'</head><body>'+html
      html=html+'</body></html>'
      output=self.OutputDir+"/"
      #print(html)
      #imgkit.from_string(html, output+ip+'-VirusTotal.jpg')
      with open(output+ip+'-VirusTotal.html', 'w') as HTMLFile:
        HTMLFile.write(html)
      #self.IMG=self.IMG+"<img src='"+ip+"-VirusTotal.jpg'><br/>"

  def updateGeneralHTML(self):
    HTMLPrefix='<html><head>'+self.HTMLHeader+'</head><body>'
    self.HTML=HTMLPrefix+self.HTML+'</body></html>'
    self.IMG=HTMLPrefix+self.IMG+'</body></html>'
    output=self.OutputDir+"/"
    with open(output+'latest-HTML-VirusTotal.html', 'w') as HTMLFile:
      HTMLFile.write(self.HTML)
    with open(output+'latest-IMG-VirusTotal.html', 'w') as HTMLFile:
      HTMLFile.write(self.IMG)

  def findPersistedIP(self,ip_id,table_name):
    self.CursorR.execute("SELECT * FROM "+table_name+" where ip_id='"+str(ip_id)+"'")
    return self.CursorR.fetchall()

  def persistResolutions(self,selected_ips,ip_report_filtered):
    attr="resolutions"
    table_name="vt_scanned_resolutions_table"
    newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
    selected_domains=self.findPersistedIP(selected_ips[0]['id'],table_name)
    selected_domains_filtered=[]
    for selected_domain in selected_domains:
      selected_domains_filtered.append(selected_domain['domain'])
    if newAttr in ip_report_filtered:
     for domain in ip_report_filtered[newAttr]:
      if domain['Domain'] not in selected_domains_filtered:
        try:
          self.CursorRW.execute("INSERT INTO "+table_name+" (ip_id,domain,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+domain['Domain']+"','"+domain['Date resolved']+"')")
          self.DBRW.commit()
          self.resetSQL()
        except Exception as e:
          print("INSERT INTO "+table_name+" (ip_id,domain,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+domain['Domain']+"','"+domain['Date resolved']+"')")
          print("EXCEPTION: ",e)
          self.resetSQL()

  def persistURLs(self,selected_ips,ip_report_filtered):
    attr="detected_urls"
    table_name="vt_scanned_urls_table"
    newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
    selected_urls=self.findPersistedIP(selected_ips[0]['id'],table_name)
    selected_urls_filtered=[]
    for selected_url in selected_urls:
      selected_urls_filtered.append(selected_url['url'])
    if newAttr in ip_report_filtered:
     for url in ip_report_filtered[newAttr]:
      print(url['URL'])
      if url['URL'] not in selected_urls_filtered:
        try:
          self.CursorRW.execute("INSERT INTO "+table_name+" (ip_id,url,detections,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+url['URL']+"','"+url['Detections']+"','"+url['Scanned']+"')")
          self.DBRW.commit()
          self.resetSQL()
        except Exception as e:
          print("INSERT INTO "+table_name+" (ip_id,url,detections,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+url['URL']+"','"+url['Detections']+"','"+url['Scanned']+"')")
          print("EXCEPTION: ",e)
          self.resetSQL()

  def persistHashs(self,selected_ips,ip_report_filtered,attr,table_name):
    newAttr=self.AttrSubstitution[attr] if attr in self.AttrSubstitution else attr
    selected_hashs=self.findPersistedIP(selected_ips[0]['id'],table_name)
    selected_hashs_filtered=[]
    for selected_hash in selected_hashs:
      selected_hashs_filtered.append(selected_hash['hash'])
    if newAttr in ip_report_filtered:
     for hash in ip_report_filtered[newAttr]:
      if hash['File Hash (sha256)'] not in selected_hashs_filtered:
        try:
          self.CursorRW.execute("INSERT INTO "+table_name+" (ip_id,hash,detections,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+hash['File Hash (sha256)']+"','"+hash['Detections']+"','"+hash['Scanned']+"')")
          self.DBRW.commit()
          self.resetSQL()
        except Exception as e:
          print("INSERT INTO "+table_name+" (ip_id,hash,detections,scanned_time) VALUES ('"+str(selected_ips[0]['id'])+"','"+hash['File Hash (sha256)']+"','"+hash['Detections']+"','"+hash['Scanned']+"')")
          print("EXCEPTION: ",e)
          self.resetSQL()

  def persist(self,ip_report_api,ip_report_filtered):
    self.CursorR.execute("SELECT * FROM vt_scanned_ips_table where scanned_ip='"+ip_report_api+"'")
    selected_ips = self.CursorR.fetchall()
    if len(selected_ips)==0:
      self.CursorRW.execute("INSERT INTO vt_scanned_ips_table (scanned_ip,last_scanned_time) VALUES ('"+ip_report_api+"','"+str(int(time.time()))+"')")
      self.DBRW.commit()
      self.resetSQL()
      self.CursorR.execute("SELECT * FROM vt_scanned_ips_table where scanned_ip='"+ip_report_api+"'")
      selected_ips = self.CursorR.fetchall()
    self.persistResolutions(selected_ips,ip_report_filtered)
    self.persistURLs(selected_ips,ip_report_filtered)
    attr="detected_referrer_samples"
    table_name="vt_scanned_referring_files_table"
    self.persistHashs(selected_ips,ip_report_filtered,attr,table_name)
    attr="detected_downloaded_samples"
    table_name="vt_scanned_downloads_table"
    self.persistHashs(selected_ips,ip_report_filtered,attr,table_name)
    attr="detected_communicating_samples"
    table_name="vt_scanned_communicating_files_table"
    self.persistHashs(selected_ips,ip_report_filtered,attr,table_name)


def main(argv):
  os.chdir(os.path.dirname(os.path.abspath(__file__)))
  vt=VirusTotal()
  vt.init()
  if vt.Input==INPUT_TYPE_ARGUMENT:
    vt.IP=argv[0]
  ips_report_api=vt.getIPReportAPI()
  results=[]
  for ip_report_api in list(ips_report_api):
    vt.preHandling()
    ip_report_filtered=vt.getIPReportFiltered(ips_report_api[ip_report_api])
    if len(vt.Order)>0:
      ip_report_filtered=vt.getOrdered(ip_report_filtered)
    if vt.Persistence==PERSISTENCE_TYPE_SQL:
      vt.persist(ip_report_api,ip_report_filtered)
    vt.getHTML(ip_report_filtered,ip_report_api)
    #results[ip_report_api]=result
  if vt.GeneralOutput=="1":
    vt.updateGeneralHTML()

if __name__ == "__main__":
    main(sys.argv[1:])
