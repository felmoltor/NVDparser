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


* **vulnerabilities**: This table contains the vulnerabilities
  * vuln_id
  * cve
  * cwe
  * cvss_score
  * summary
  * published_date
  * modified_date
* **cpe**: This table contains the common platform enumeration dictionary
  * cpe_id
  * cpe_text
  * part
  * vendor
  * product
  * version
  * update_date
  * edition
  * language
* **affects_to_cpe**: This table contains the relation between the vulnerability and the cpes affected
  * affects_to_cpe_id
  * vuln_id (Foreign Key of vulnerabilities.vuln_id)
  * cpe_id  (Foreign Key of cpe.cpe_id)

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

```
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

```

Manual exportation
------------------

Examples of how to extract from the sqlite database to a CSV file.

Oneliner:
```
sqlite3 -csv -header -separator '|' nvd.vulnerabilities.db 'select cve,cvss_score,vendor,product,version,update_date,edition,language,summary from vulnerabilities v inner join affects_to_cpe ac on v.vuln_id = ac.vuln_id inner join cpe c on ac.cpe_id = c.cpe_id where c.vendor = "microsoft" and c.product like "%windows%2008%"' > windows_2008.all.editions.csv
```

Within the sqlite file:
```
user@host:~/Tools/NVDparser$ sqlite3 nvd.vulnerabilities.db
SQLite version 3.8.6 2014-08-15 11:46:33
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode csv
sqlite> .separator "|"
sqlite> .out cve20063823.csv
sqlite> select cve,cvss_score,summary,vendor,product,version from vulnerabilities v inner join affects_to_cpe ac  on v.vuln_id = ac.vuln_id inner join cpe c on ac.cpe_id = c.cpe_id where v.cve = 'CVE-2006-3823';
sqlite> .q
user@host:~/Tools/NVDparser$ cat cve20063823.csv
cve|cvss_score|summary|vendor|product|version
CVE-2006-3823|5.1|"SQL injection vulnerability in index.php in GeodesicSolutions (1) GeoAuctions Premier 2.0.3 and (2) GeoClassifieds Basic 2.0.3 allows remote attackers to execute arbitrary SQL commands via the b parameter."|geodesicsolutions|geoauctions_premier|2.0.3
CVE-2006-3823|5.1|"SQL injection vulnerability in index.php in GeodesicSolutions (1) GeoAuctions Premier 2.0.3 and (2) GeoClassifieds Basic 2.0.3 allows remote attackers to execute arbitrary SQL commands via the b parameter."|geodesicsolutions|geoclassifieds_basic|2.0.3
```
