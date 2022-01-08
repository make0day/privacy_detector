from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
             
import re
from java.net import URL
from java.util.regex import *
from java.lang import *
import json
import os

'''
class PII(Enum):
    DriverLicenseNo = 1
    BankAccountNo = 2
    PassportNo = 3
    IpAddress = 4
    HomeAddress = 5
    MobileNo = 6
    PhoneNo = 7
'''

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Privacy Detector")

        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)       

        self.__stdout.println("Privacy Detector Loaded")

        #Loads patterns file
        f = open("./patterns.json", "r")
        patternFile = json.load(f)
        f.close()

        #precompile regex patterns for better performance
        self.__regexs = dict()
        for pattern in patternFile['patterns']:
            if pattern['use'] == True:
                self.__regexs[(re.compile(pattern['expression']))] = pattern['type']
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return

    
    def getTabCaption(self):
        return "Privacy Detector"
    
    def getUiComponent(self):
        return self._splitpane
        

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()

        # the condition check if the inScope variable is true or false; in the first case it checks if the httpProxyItem respects the "in scope" condition
        try:
            if messageInfo != None:
                #httpService = messageInfo.getHttpService()
                Url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                #Host = httpService.getHost()
                #Protocol = httpService.getProtocol()
                #self.__stdout.println("test = {} {} {}".format(len(Host),len(Protocol),len(Url)))

                Path = URL(Url).getPath()
                '''
                    Cases : 
                                /api/v1/
                                /api/v2/
                                /api/v3/
                                /api/v4/
                                /api/hello
                                /api/users/me
                '''

                # if only path starts with '/api/'
                if Path.lower().startswith("/api/"):

                    #self.__stdout.println(Path)

                    # Get Response and analyze it
                    httpProxyItemResponse = self._helpers.analyzeResponse(messageInfo.getResponse())

                    # Do not anything if http status code is one of error type
                    if httpProxyItemResponse.getStatusCode() not in [401, 402, 403, 404, 405, 500, 502]:
                        #Get mime type of HTTP response
                        mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                        if mimeType == "":
                            mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                        #self.__stdout.println("mimeType = {}".format(mimeType))

                        #Check content type one of json types
                        if mimeType == 'json':
                    
                            #Get the response body
                            responseBody = self._helpers.bytesToString(messageInfo.getResponse())

                            responseLength = ''
                            #Get header length
                            for header in httpProxyItemResponse.getHeaders():
                                if header.lower().startswith("content-length:"):
                                    responseLength = header.split(":")[1].lower()
                                    break

                            if responseLength == '':
                                responseLength = len(responseBody)

                            #self.__stdout.println("responseLength = {}".format(responseLength))

                            if responseLength != '':

                                #responseheaderLength = len(httpProxyItemResponse.getHeaders().toString())
                                #if responseLength < responseheaderLength:
                                if httpProxyItemResponse.getBodyOffset() != 0:
                                    responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]

                                #self.__stdout.println(responseBody)
                                #self.__stdout.println("bodyLength = {}".format(responseLength))
                                #self.__stdout.println("headerLength = {}".format(responseheaderLength))

                                for regex in self.__regexs.keys():
                                    matchobj = regex.search(responseBody)
                                    if matchobj != None:
                                        self.__stdout.println(Path)
                                        self.__stdout.println("Matched = {}".format(matchobj.group()))
                                        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), matchobj.group(), self.__regexs.get(regex), self._helpers.analyzeRequest(messageInfo).getMethod()))
          
        except Exception as e:
            self.__stdout.println(e)
    
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 5

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Method"
        if columnIndex == 3:
            return "Matched Pattern"
        if columnIndex == 4:
            return "PII Type"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return str(rowIndex)
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._url.toString()
        if columnIndex == 3:
            return logEntry._matched
        if columnIndex == 4:
            return logEntry._piitype
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, matched, piitype, method):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._matched = matched
        self._piitype = piitype
        self._method = method