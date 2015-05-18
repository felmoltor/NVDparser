#!/usr/bin/python

# Author: Felipe Molina (@felmoltor)
# Date: 05/2015
# Summary:    Download nvd.nist.gov XML files containing CVE details.
#             Parse it and saves in sqlite3 db
# LICENSE: GPLv2

from mechanize import *
from lxml import etree
import os
import datetime
import time
import gzip
import sqlite3
import re 
from termcolor import colored
from optparse import OptionParser

DLPAGE="https://nvd.nist.gov/download.cfm"
DBNAME="nvd.vulnerabilities.db"
OUTPUTFILE="%s_output.csv" % (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
VERSION="0.1"

def printBanner():
    print colored("=====================================================","blue","on_white")
    print colored("=     NVD vulnerability downloader & parser v%s    =" % VERSION,"blue","on_white")
    print colored("=         DOWNLOADER / IMPORTER / EXPORTER          =","blue","on_white")
    print colored("=        Author: Felipe Molina (@felmoltor)         =","blue","on_white")
    print colored("= Source XML from %s =" % DLPAGE,"blue","on_white")
    print colored("=====================================================","blue","on_white")
    print

def getoptions():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Show CVE being parsed by the script [default: False]")
    parser.add_option("-d", "--database",metavar="FILE",dest="database", default=DBNAME, help="Database file where to save the vulnerabilities")
    parser.add_option("-s", "--sqlquery",dest="sqlquery", default=None, help="SQL query to export from the database")
    parser.add_option("-o", "--output",dest="outfile", default=OUTPUTFILE, help="Output file name")
    (options,args) = parser.parse_args()
    if options.database is None:
        parser.error("You have to specify a sqlite3 database file (-d, --database)")
    return options

def initDatabase(dbname):
    if (not os.path.isfile(dbname)):
        print "Database file does not exists. Initializing it"
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS download_dates (
                    dldate_id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    download_link TEXT, 
                    feed_year TEXT,
                    feed_size REAL,
                    last_download INTEGER)''')
    # CPE format (like URL)
    # cpe:/ {part} : {vendor} : {product} : {version} : {update} : {edition} : {language}
    # Part - Determines the platform type using the following codes: a = application, h = hardware, o = operating system
    # Vendor - Defines the vendor name as the "highest organization-specific label of the organization's DNS name", which, in our case, would be "Tenable Security".
    # Product - Product name as specified in the CPE database, e.g., itunes, quicktime and firefox
    # Version - The version numbers as represented by the product itself.
    # Update - The CPE name for the update or service pack, such as "Service Pack 3" in the case of Windows XP.
    # Edition - The edition of the software, such as "pro" for "Professional Edition". For hardware, this would also denote the architecture, such as "i386".
    # Language - For example, "English" or other language as specified by the software.
    c.execute('''CREATE TABLE IF NOT EXISTS cpe (
                    cpe_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cpe_text TEXT,
                    part TEXT,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    update_date TEXT,
                    edition TEXT,
                    language TEXT
                    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS affects_to_cpe (
                    affects_to_cpe_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id INT,
                    cpe_id INT,
                    FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(vuln_id),
                    FOREIGN KEY(cpe_id) REFERENCES cpe(cpe_id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id integer PRIMARY KEY AUTOINCREMENT,
                    cve TEXT UNIQUE,
                    cvss_score REAL,
                    cwe TEXT,
                    summary TEXT,
                    published_date INT,
                    modified_date INT,
                    dldate_id INT,
                    FOREIGN KEY(dldate_id) REFERENCES download_dates(dldate_id))''')
    c.execute('''CREATE INDEX IF NOT EXISTS vulncve_idx ON vulnerabilities(cve)''')
    
    
    return conn

def closeDatabase(conn):
    conn.close()

def storeDownloadDate(conn,dl_link,feed_year,feed_size,last_donwload):
    cur = conn.cursor()
    res = cur.execute('''INSERT INTO cpe(cpe_text,part,vendor,product,version,update_date,edition,language) VALUES(?,?,?,?,?,?,?,?)''',(cpe_text,part,vendor,product,version,update,edition,language))
    pk=cur.lastrowid
    conn.commit()
    return pk

def searchCPE(conn,cpe_text):
    cpe_id = None
    cur = conn.cursor()
    res = cur.execute('''SELECT cpe_id FROM cpe WHERE cpe_text = ? LIMIT 1''',(cpe_text,))
    results = res.fetchall()
    if len(results) > 0:
        cpe_id = results[0][0]
    return cpe_id

def storeDlDate(conn,dllink,feed_year,feed_size):
    dlepoch = int(time.time())
    cur = conn.cursor()
    res = cur.execute('''INSERT INTO download_dates(download_link,feed_year,feed_size,last_download) VALUES(?,?,?,?)''',(dllink,feed_year,feed_size,dlepoch))
    pk=cur.lastrowid
    conn.commit()
    return pk

def storeCPE(conn,cpe_text):
    part=vendor=product=version=update=edition=language = '?'
    cpesplit=cpe_text.split(":")
    # In some cases, the CPE text does not contains all the 7 fields. Check wich is available
    if len(cpesplit)>1 and cpesplit[1] is not None:
        part=cpesplit[1]
    if len(cpesplit)>2 and cpesplit[2] is not None:
        vendor=cpesplit[2]
    if len(cpesplit)>3 and cpesplit[3] is not None:
        product=cpesplit[3]
    if len(cpesplit)>4 and cpesplit[4] is not None:
        version=cpesplit[4]
    if len(cpesplit)>5 and cpesplit[5] is not None:
        update=cpesplit[5]
    if len(cpesplit)>6 and cpesplit[6] is not None:
        edition=cpesplit[6]
    if len(cpesplit)>7 and cpesplit[7] is not None:
        language=cpesplit[7]
    
    cur = conn.cursor()
    res = cur.execute('''INSERT INTO cpe(cpe_text,part,vendor,product,version,update_date,edition,language) VALUES(?,?,?,?,?,?,?,?)''',(cpe_text,part,vendor,product,version,update,edition,language))
    pk=cur.lastrowid
    conn.commit()
    return pk

def storeAffectsToCPE(vulnid,cpeid):
    cur = conn.cursor()
    res = cur.execute('''INSERT INTO affects_to_cpe(cpe_id,vuln_id) VALUES(?,?)''',(cpeid,vulnid))
    pk=cur.lastrowid
    conn.commit()
    return pk

def storeVuln(cve,cvss_score,cwe,summary,published_date,modified_date,cpetextlist):
    cpeid = None
    vulnpk = None
    cur = conn.cursor()
    # datesformat: "2015-05-11T21:59:13.853-04:00"
    published_date=published_date.split(".")[0]
    modified_date=modified_date.split(".")[0]
    pubepoch=int(time.mktime((time.strptime(published_date,"%Y-%m-%dT%H:%M:%S"))))
    modepoch=int(time.mktime((time.strptime(modified_date,"%Y-%m-%dT%H:%M:%S"))))
    
    res = cur.execute('''INSERT INTO vulnerabilities(cve,cvss_score,cwe,summary,published_date,modified_date) VALUES(?,?,?,?,?,?)''',(cve,cvss_score,cwe,summary,pubepoch,modepoch))
    vulnpk=cur.lastrowid
    conn.commit()
    # save the cpe list
    for cpetext in cpetextlist:
        cpeid = searchCPE(conn,cpetext)
        if cpeid is None:
            cpeid = storeCPE(conn,cpetext)
            
        storeAffectsToCPE(vulnpk,cpeid)

    return vulnpk

def hasToBeUpdated(conn,dllink,updatedepoch):
    lastdownload = 0
    cur = conn.cursor()
    res = cur.execute('''SELECT last_download FROM download_dates WHERE download_link = ? LIMIT 1''',(dllink,))
    results = res.fetchall()
    if len(results) > 0:
        lastdownload = results[0][0]
    # compare the last time we updated this link with the updated date shown in the web page 
    return lastdownload < updatedepoch

def isVulnInDatabase(conn,cveid):
    cur = conn.cursor()
    res = cur.execute('''SELECT vuln_id FROM vulnerabilities WHERE cve = ? LIMIT 1''',(cveid,))
    results = res.fetchall()
    return len(results) > 0

def wasVulnUpdated(conn,cveid,modified):
    modified_date = 0
    cur = conn.cursor()
    modified=modified.split(".")[0]
    modepoch=int(time.mktime((time.strptime(modified,"%Y-%m-%dT%H:%M:%S"))))
    res = cur.execute('''SELECT modified_date FROM vulnerabilities WHERE cve = ? LIMIT 1''',(cveid,))
    results = res.fetchall()
    if len(results) > 0:
        modified_date = results[0][0]
    return modepoch > modified_date

def updateVuln(conn,cveid,cvss,cwe,summary,published_date,modified_date,cpetextlist):
    cpeid = None
    vuln_id = None
    cur = conn.cursor()
    # datesformat: "2015-05-11T21:59:13.853-04:00"
    published_date=published_date.split(".")[0]
    modified_date=modified_date.split(".")[0]
    pubepoch=int(time.mktime((time.strptime(published_date,"%Y-%m-%dT%H:%M:%S"))))
    modepoch=int(time.mktime((time.strptime(modified_date,"%Y-%m-%dT%H:%M:%S"))))
    
    res = cur.execute('''SELECT vuln_id FROM vulnerabilities WHERE cve = ? LIMIT 1''',(cveid,))
    results = res.fetchall()
    if len(results) > 0:
        vuln_id = results[0][0]
        
    # Delete the previous affected CPEs and insert the new ones
    res = cur.execute('''DELETE FROM affects_to_cpe WHERE vuln_id=?''',(vuln_id))
    
    res = cur.execute('''UPDATE vulnerabilities
        SET cve=?,cvss_score=?,cwe=?,summary=?,published_date=?,modified_date=? 
        WHERE vuln_id=?
    ''',(cve,cvss_score,cwe,summary,pubepoch,modepoch,cve,vuln_id))
    vulnpk=cur.lastrowid
    conn.commit()
    
    # save the cpe list
    for cpetext in cpetextlist:
        cpeid = searchCPE(conn,cpetext)
        if cpeid is None:
            cpeid = storeCPE(conn,cpetext)
            
        storeAffectsToCPE(vuln_id,cpeid)

    return vuln_id

##################
###### MAIN ######
##################

printBanner()
options = getoptions()

# Parse the vuln download page
br = Browser()
conn = initDatabase(options.database)

br.open(DLPAGE)
body=br.response().read()
# Visit first page of wordpress.org/plugins
html=etree.HTML(body)

feedtable = html.xpath("//table[@class='xml-feed-table']")[0]

nrow=0
for trow in feedtable.xpath("tbody/tr"):
    nrow += 1
    feed = updated = dllink = size = ""
    colnum = 0
    if ((nrow % 2) == 1):
        for col in trow.xpath("td"):
            colnum += 1
            if colnum == 1:
                feed = col.text
            if colnum == 2:
                updated = col.text
                updatedepoch=int(time.mktime((time.strptime(updated,"%m/%d/%Y"))))
            if colnum == 3:
                dllink = col.xpath("a")[0].get("href")
            if colnum == 4:
                size = float(col.text)
            # Ignore the rest of the columns
            if colnum > 4:
                break

        # Ignore the second line of the table, as the feed name occupies two rows
        if feed is not None:
            # Check if this file has been updated since the last download we made
            if hasToBeUpdated(conn,dllink,updatedepoch):
                print colored("File %s is not up to date. Downloading now." % dllink,"red")
                print "%s: Updated %s, downloadig %sMB from %s" % (feed,updated,size,dllink)
                dlname = dllink.split("/").pop()
                # Download the link with the XML
                br.retrieve(dllink,dlname)
                # Save as downloaded
                storeDlDate(conn,dllink,feed,size)
                # Unzip and parse the file to store it in sqlite3
                g = gzip.open(dlname,"rb")
                gcontent = g.read()
                g.close() # Free memory
                g = None
                print "Now, importing content of the file %s" % dlname
                ifxml = etree.XML(gcontent)
                gcontent = None # Free memory
                for entry in ifxml.getchildren():
                    # print entry.getchildren()
                    cwe = summary = cveid = "?"
                    cvss = 0.0
                    modified = published = ""
                    cpetextlist = []
                    
                    cwee = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cwe")
                    if cwee is not None:
                        cwe = cwee.values()[0]

                    cvsseleme =entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cvss") 
                    if cvsseleme is not None:
                        cvsselem = cvsseleme.getchildren()[0]
                        cvss = float(cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}score").text)
                    
                    modifiede = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}last-modified-datetime")
                    if modifiede is not None:
                        modified = modifiede.text
                    
                    publishede = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}published-datetime")
                    if publishede is not None:
                        published = publishede.text
                    
                    cveide = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cve-id")
                    if cveide is not None:
                        cveid = cveide.text

                    summarye = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}summary")
                    if summarye is not None:
                        summary = summarye.text

                    cpeliste = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list")
                    if cpeliste is not None:
                        for cpee in cpeliste.getchildren():
                            cpetextlist.append(cpee.text)

                    if (options.verbose):
                        print colored("=================","cyan")
                        print colored(" = %s =" % cveid,"cyan") 
                        print colored("=================","cyan")
                        print " * cwe: %s" % cwe
                        print " * cvss: %s" % cvss
                        print " * modified: %s" % modified
                        print " * published: %s" % published
                        print " * summary: %s" % summary
                        print " * N of cpe: %s" % len(cpetextlist)
                    
                    if (not isVulnInDatabase(conn,cveid)):
                        storeVuln(cveid,cvss,cwe,summary,published,modified,cpetextlist)
                    else:
                        if (wasVulnUpdated(conn,cveid,modified)):
                            print colored("Vulnerability %s has been updated. Updating in database" % cveid,"yellow")
                            updateVuln(conn,cveid,cvss,cwe,summary,published,modified,cpetextlist)
                        else:
                            print colored("Vulnerability %s is already in the database" % cveid,"red")
                    

            else:
                print colored("File %s is up to date. Not downloading." % dllink,"green")


closeDatabase(conn)
