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
- 1) Send log to Splunk server :  The plugin will send send logs to Splunk server with JSON request.
- - Options :
- - 1. SplunkHost : Your log server host name, ex : splunklogserver
- - 2. SplunkToken : Splunk server API token, ex : pleasefillyoursplunktoken
- - 3. SplunkSleep : Logging interval, ex : 5 (Every 5 Mins)
- - 4. SplunkAutoSend : Whether use auto send log or not, ex: 1=no, 2=yes
- 2) Send log as a .csv file : The PII detection results can be exported in .CSV format.
- 3) Clear history : The function to clear logs.
5. Configuration:
- 1) Top list refresh : Turn on and off refresh Top hit list (Default : ON)
- 2) Search : Whether to find all cases that exist within a web page or just one case. (Default : Find all)
- 3) Scan : Quick Scan (JSON only) / Deep Scan (JSON/XML/HTML/TEXT) / Full Scan (Except Images)

## Supported formats

Category | Level | Type | Description
---- | ---- | ---- | ----
PII | Medium | MobileNumber | Mobile cell phone number information
PII | Medium | PhoneNumber | Telephone number information
PII | Medium | EmailAddress | Email address information
PII | Medium | ResidentRegistrationNumber | Resident Registration Number(RRN) information
PII | High | ResidentRegistrationNumber | Corporate registration number information
PII | Low | BusinessRegistrationNumber | Resident Registration Number(RRN) information
PII | High | NationalInsuranceNumber | National insurance number information
PII | High | PCCCNumber | Personal customs clearance code information
PII | High | ForeinerRegistrationNumber | Foreiner registration number information
PII | High | PassportNumber | Passport number information
PII | High | CreditCardNumber | Credit card number information
PII | High | MasterCardNumber | Credit card number information
PII | High | VisaCardNumber | Credit card number information
PII | High | AmexCardNumber | Credit card number information
PII | High | DriverLicenseNumber | Driver license number information
PII | High | BankAccountNumber | Bank account number information
PII | Medium | RoadAddress | Address information
PII | Medium | KoreanName | Profile name information
PII | Low | Ipv4Address | IP v4 address information
PII | Low | URLAddress | URL address information
PII | Medium | URLAddress | MAC address information
CREDENTIAL | Info | AccessKeyType | Multi type potential access key information
CREDENTIAL | Critical | AWSSessionToken | AWS session token information
CREDENTIAL | High | AWSAccessKey | AWS access key information
CREDENTIAL | High | TencentSecretId | Tencent secret ID information
CREDENTIAL | High | GoogleAPIToken | Google API token information
CREDENTIAL | Critical | AWSSecretKey | AWS secret key information
CREDENTIAL | Critical | PrivateSecureKey | Private secure key information
CREDENTIAL | High | AuthorizationBasic | Authorization basic information
CREDENTIAL | High | AuthorizationBearer1 | Authorization bearer information
CREDENTIAL | High | AuthorizationBearer2 | Authorization bearer information
CREDENTIAL | High | AuthorizationAPI | Authorization API information
CREDENTIAL | High | GoogleOAuthToken | Google OAuth token information
CREDENTIAL | High | GoogleOAuthKey | Google OAuth key information
CREDENTIAL | High | FacebookAuthToken | Facebook Auth token information

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

**1.0.1**

* Jan / 13 / 2022: Privacy Detector is integrated with Burp Spider Now!

Please refer to the next page to see how to set it up : 
[How to configure Burp Scanner Spider feature](https://github.com/make0day/privacy_detector/wiki/How-to-configure-Burp-Scanner---Spider-feature)

