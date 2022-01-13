# HTTP Privacy Detector for Burp Suite

## Introduction

Privacy Detector is a Burp Suide plugin extracts privacy information from HTTP responses automatically

## Installation

To install Privacy Detector, you have to:

1. Visit Jython Offical Site, and download Jython Installer.
2. Open Jython Installer to install Jython(In standard mode, make sure it will install pip). 
3. Download newest Privacy Detector from the Release page
4. Go to Extender -> Extension. Click Add. Set Extension type to Python. Set the path of the file download at step 1.
   inside Extension file (.py)
5. Privacy Detector should appear inside Burp Extension list. Also you will see a new tab.

## Usage

1. Live PII Detection : Privacy Detector will parse all http history generated from that moment and it will find any PII.
2. Parse Full HTTP history : The plugin will parse full requests history.
3. Top Hit URL Dashboard : Dashboard to see which URLs are frequently contain PII.
4. Others : 
- 1) Send log to SIEM server :  The plugin will send send logs to the server with JSON request.
- 2) Send log as a .csv file : The PII detection results can be exported in .CSV format.
- 3) Clear history : The function to clear logs.
5. Configuration:
- 1) Top list refresh : Turn on and off refresh Top hit list (Default : ON)
- 2) Search : Whether to find all cases that exist within a web page or just one case. (Default : Find all)
- 3) Scan : Quick Scan (JSON only) / Deep Scan (JSON/XML/HTML/TEXT) / Full Scan (Except Images)

## Credits

Privacy Detector was born in 2022 by Koo Brothers, for finding privacy information from HTTP responses automatically.
- Samuel Koo - 0day@kakao.com 
- Daniel Koo - reby7146@me.com

## References

- [PortSwigger Burp API Reference](https://portswigger.net/burp/extender/api/burp/package-summary.html): PortSwigger Official Burp API Reference.

## Links

- [PCap Importer Extender for Burp](https://portswigger.net/bappstore/01da4fdd9f6e4e12b0622fbdaa2dd26d): This extension enables Pcap and Pcap-NG files to be imported into the Burp.

## Change log

**1.0.0**

* Jan / 10 / 2022: Creation of the extension and initial release.

