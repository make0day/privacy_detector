#!/usr/bin/env python
#coding=utf8
#
#     
#                    Privacy Detector Project
#
#                           
#                        Github : https://github.com/make0day/privacy_detector
#
#
#     
#                        Coded by Samuel Koo ( 0day@kakao.com )
#
#                                   and
#
#                                 Daniel Koo ( reby7146@me.com )
#
#
#
#
import sys
import os
import json
import re
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
from javax.swing import JPanel;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
from java.net import URL
from java.util.regex import *
from java.lang import *
from datetime import datetime
#import requests



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
        #self.__stdout.setCharacterEncoding("UTF-8")  

        self.__stdout.println("Privacy Detector Loaded")
        self.__stdout.println("Coded by Samuel Koo & Daniel Koo")
        self.__stdout.println("Project github : https://github.com/make0day/privacy_detector")


        # 1 = Single Scan, 2 = Recursive PII Scan, 3 = Full Scan (All Mime Type)
        self.__scanningLevel = 2
        self.__stdout.println("[+] Current Scanning Level is : {}".format(self.__scanningLevel))

        try:
            #Loads patterns file
            self.__stdout.println("[+] Load PII patters from json file...")
            if os.path.exists("./patterns.json"):
                f = open("./patterns.json", "r")
            else:
                #url = 'https://github.com/make0day/privacy_detector/blob/main/patterns.json'
                #response = requests.get(url)
                f = open("./patterns.json", "rw")
                #f.write(response.text)

            keys = f.read().decode('utf-8')
            patternFile = json.loads(keys)
            f.close()

            #precompile regex patterns for better performance
            self.__regexs = dict()
            for pattern in patternFile['patterns']:
                if pattern['use'] == True:
                    #self.__stdout.println("[{}] {}".format(pattern['type'], pattern['expression'].encode('utf-8')))
                    self.__regexs[(re.compile(pattern['expression'].encode('utf-8')))] = pattern['type']
        except Exception as e:
            self.__stdout.println(e)
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        #self._splitpane.setResizeWeight(0.2)

        # table of log entries
        logTable = Table(self)
        logTable.setAutoResizeMode(Table.AUTO_RESIZE_OFF)
        logTable.getColumnModel().getColumn(0).setPreferredWidth(50)
        logTable.getColumnModel().getColumn(1).setPreferredWidth(100)
        logTable.getColumnModel().getColumn(2).setPreferredWidth(750)
        logTable.getColumnModel().getColumn(3).setPreferredWidth(400)
        logTable.getColumnModel().getColumn(4).setPreferredWidth(350)
        logTable.getColumnModel().getColumn(5).setPreferredWidth(200)

        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        #panelRequest = JPanel()
        #panelResponse = JPanel()

        #panelRequest.add(self._requestViewer.getComponent())
        #panelResponse.add(self._responseViewer.getComponent())

        #self._splitbottompane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        #self._splitbottompane.setResizeWeight(0.5)

        #self._splitbottompane.setLeftComponent(panelRequest)
        #self._splitbottompane.setRightComponent(panelResponse)

        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        #self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._splitpane, self._splitbottompane);
        
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
    

    def AddLogEntry(self, tool, requestResponse, url, matched, piitype, method):
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(tool, requestResponse, url, matched, piitype, method))
        self.fireTableRowsInserted(row, row)
        self._lock.release()
        return

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        

        # the condition check if the inScope variable is true or false; in the first case it checks if the httpProxyItem respects the "in scope" condition
        try:
            if messageInfo != None:
                #httpService = messageInfo.getHttpService()
                #Host = httpService.getHost()
                #Protocol = httpService.getProtocol()
                #self.__stdout.println("test = {} {} {}".format(len(Host),len(Protocol),len(Url)))

                # if only path starts with '/api/'
                #Url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                #Path = URL(Url).getPath()
                #if Path.lower() != '/api/v2/api-docs': #Path.lower().startswith("/api/"):
                #self.__stdout.println(toolFlag)

                #From Proxy
                if toolFlag == 4:


                    # Get Response and analyze it
                    httpProxyItemResponse = self._helpers.analyzeResponse(messageInfo.getResponse())

                    # Do not anything if http status code is one of error type
                    if httpProxyItemResponse.getStatusCode() not in [301, 302, 307, 401, 402, 403, 404, 405, 406, 408, 411, 500, 502, 503]:
                        #Get mime type of HTTP response
                        mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                        if mimeType == "":
                            mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                        #self.__stdout.println("mimeType = {}".format(mimeType))

                        #Check content type one of json types or scanningLevel == 3
                        if  mimeType == 'json' or (self.__scanningLevel == 3 and mimeType == 'xml'): #javascript script html text
                    
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
                                if httpProxyItemResponse.getBodyOffset() != 0:
                                    responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]

                                #self.__stdout.println(responseBody)
                                #self.__stdout.println("Matched = {} ".format(matched))

                                for regex in self.__regexs.keys():
                                    if self.__scanningLevel == 1:
                                        matchobj = regex.search(responseBody)
                                        if matchobj != None:
                                            matched = unicode(matchobj.group().decode('utf-8'),'utf-8')
                                            self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), matched, self.__regexs.get(regex), self._helpers.analyzeRequest(messageInfo).getMethod())
                                    elif self.__scanningLevel > 1:
                                        matchObj_iter = regex.finditer(responseBody)
                                        if matchObj_iter != None:
                                            for matchobj in matchObj_iter:
                                                matched = unicode(matchobj.group().decode('utf-8'),'utf-8')
                                                self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), matched, self.__regexs.get(regex), self._helpers.analyzeRequest(messageInfo).getMethod())

        except Exception as e:
            self.__stdout.println(e)
    

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 6

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Method"
        if columnIndex == 2:
            return "URL"
        if columnIndex == 3:
            return "Matched Pattern"
        if columnIndex == 4:
            return "PII Type"
        if columnIndex == 5:
            return "Time"
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
        if columnIndex == 5:
            return logEntry._time
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
        self._time = datetime.now().strftime("%Y_%m_%d_%H:%M:%S")



