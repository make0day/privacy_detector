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

1. Live PII Detect : Privacy Detector will parse all http history generated from that moment and it will find any PII.
2. Parse Full HTTP history : the plugin will parse full requests history.
3. Options : 
- 1) Send log to SIEM server
- 2) Send log as a file
- 3) Clear history

## Credits

Privacy Detector was born in 2022 by Koo brothers, for finding privacy information from HTTP responses automatically.

## Version Changes

- Jan / 10 / 2022 Initial Release

