# NVDparser

Summary
-------
This scripts access to NVD (National Vulnerability Database) web page, download XML files from https://nvd.nist.gov/download.cfm, parses them and stores in sqlite3 database.
The script will not download files already downloaded if the update date is not more recent than the last time it was downloaded.
The script also ignores the vulnerabilities is they are already inserted in the database and the modified date is not more recent than the last time the vulnerability was downloaded.

*TODO*: Exportation is not yet implemented.

Database Structure
------------------

Created tables and columns: 
* *vulnerabilities*: This table contains the vulnerabilities
** vuln_id
** cve
** cwe
** cvss_score
** summary
** published_date
** modified_date

* *cpe*: This table contains the common platform enumeration dictionary
** cpe_id
** cpe_text
** part
** vendor
** product
** version
** update_date
** edition
** language

* *affects_to_cpe*: This table contains the relation between the vulnerability and the cpes affected
** affects_to_cpe_id
** vuln_id
** cpe_id


Usage
-----

```
Usage: nvdparser.py [options]

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Show CVE being parsed by the script [default: False]
  -d FILE, --database=FILE
                        Database file where to save the vulnerabilities
  -s SQLQUERY, --sqlquery=SQLQUERY
                        SQL query to export from the database
  -o OUTFILE, --output=OUTFILE
                        Output file name
```

Output Example
--------------

parserNVD$ ./nvdparser.py -d nvd.vulnerabilities.db
=====================================================
=     NVD vulnerability downloader & parser v0.1    =
=         DOWNLOADER / IMPORTER / EXPORTER          =
=        Author: Felipe Molina (@felmoltor)         =
= Source XML from https://nvd.nist.gov/download.cfm =
=====================================================

Database file does not exists. Initializing it
File http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz is not up to date. Downloading now.
Modified: Updated 5/17/2015, downloadig 0.35MB from http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz
Now, importing content of the file nvdcve-2.0-Modified.xml.gz
File http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz is not up to date. Downloading now.
Recent: Updated 5/17/2015, downloadig 0.03MB from http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz
Now, importing content of the file nvdcve-2.0-Recent.xml.gz
Vulnerability CVE-2012-5849 is already in the database
Vulnerability CVE-2014-1900 is already in the database
[...]


