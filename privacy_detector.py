#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
#     
#                    Privacy Detector Project
#
#                           
#                        Github : https://github.com/make0day/privacy_detector
#
#                        Written by Samuel Koo ( 0day@kakao.com )
#
#                                   and
#
#                                 Daniel Koo ( reby7146@me.com )
#
import sys
import os
import json
import re
from datetime import datetime
from threading import Lock

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IMessageEditorController

from java.awt.event import ActionListener
from java.awt import Component, Color, Font
from java.awt import BorderLayout, FlowLayout, GridLayout
from javax.swing import SwingUtilities
from javax.swing import JButton,JTable, JLabel, JProgressBar, JTree, ButtonGroup, BorderFactory
from javax.swing import JPanel, JOptionPane, JScrollPane, JSplitPane, JTabbedPane
from javax.swing.table import AbstractTableModel
from java.lang import Thread, Runnable
from java.lang import *
from java.util import ArrayList, List
from java.util.regex import *
from java.io import PrintWriter
from java.net import URL

#
# implement IBurpExtender
#

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # Precompile Regex rulesets
    #
    def PrecompilePIIRuleSets(self, patternFile):
        try:
            #precompile regex patterns for better performance
            self.__regexs = dict()
            for pattern in patternFile['patterns']:
                if pattern['use'] == True:
                    #self.__stdout.println("[{}] {}".format(pattern['type'], pattern['expression'].encode('utf-8')))
                    self.__regexs[(re.compile(pattern['expression'].encode('utf-8')))] = pattern['type']
        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # Load Ruleset file
    #
    def LoadRulesetFile(self):
        patternFile = None
        try:
            #Loads patterns file
            if os.path.exists("./patterns.json"):
                f = open("./patterns.json", "r")
            else:
                #url = 'https://github.com/make0day/privacy_detector/blob/main/patterns.json'
                #response = requests.get(url)
                f = open("./patterns.json", "r")
                #f.write(response.text)

            keys = f.read().decode('utf-8')
            patternFile = json.loads(keys)
            f.close()
        except Exception as e:
            self.__stdout.println(e)
        return patternFile

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


        # 1 = Json Only Scan, 2 = Json,XML,Text,HTML Scan, 3 = Full Scan (Except images)
        self.__scanningType = 1
        self.__stdout.println("[+] Current Scanning Mime Type : {}".format(self.__scanningType))

        # 1 = Find one item from the page, 1 > = Find all items
        self.__scanningDepth = 2
        self.__stdout.println("[+] Current Scanning Depth : {}".format(self.__scanningDepth))

        self.__stdout.println("[+] Load PII patters from json file...")
        patternFile = self.LoadRulesetFile()
        self.PrecompilePIIRuleSets(patternFile)
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.2)

        # table of log entries
        logTable = Table(self)
        logTable.setAutoResizeMode(Table.AUTO_RESIZE_OFF)
        logTable.getColumnModel().getColumn(0).setPreferredWidth(50)
        logTable.getColumnModel().getColumn(1).setPreferredWidth(100)
        logTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        logTable.getColumnModel().getColumn(3).setPreferredWidth(550)
        logTable.getColumnModel().getColumn(4).setPreferredWidth(350)
        logTable.getColumnModel().getColumn(5).setPreferredWidth(300)
        logTable.getColumnModel().getColumn(6).setPreferredWidth(250)
        self._logTable = logTable

        scrollPane = JScrollPane(logTable)
        self._scrollPane = scrollPane
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        #self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        #panelRequest.add(self._requestViewer.getComponent())
        #panelResponse.add(self._responseViewer.getComponent())

        #self._splitbottompane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        #self._splitbottompane.setResizeWeight(0.5)

        #self._splitbottompane.setLeftComponent(panelRequest)
        #self._splitbottompane.setRightComponent(panelResponse)

        #tabs.addTab("Request", self._requestViewer.getComponent())
        
        tabPaneController = JPanel()
        tabPaneController.setLayout(BorderLayout())


        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        #self._splitpane.setRightComponent(self._responseViewer.getComponent())

        tabs.addTab("Options", tabPaneController)
        btnList = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))


        btnSendLog = JButton("Send log to the server")
        btnList.add(btnSendLog,BorderLayout.NORTH)
        btnSendLog.setSize(300, 300)
        btnSendLog.addActionListener(StartSendLog(self))

        btnSaveFile = JButton("Save log as a file")
        btnList.add(btnSaveFile,BorderLayout.SOUTH)
        btnSaveFile.setSize(300, 300)
        btnSaveFile.addActionListener(StartSaveFile(self))

        btnParseFullHTTP = JButton("Parse Full history")
        btnList.add(btnParseFullHTTP,BorderLayout.EAST)
        btnParseFullHTTP.setSize(300, 300)
        btnParseFullHTTP.addActionListener(StartParseFullHTTP(self))

        btnClearHistory = JButton("Clear history")
        btnList.add(btnClearHistory,BorderLayout.CENTER)
        btnClearHistory.setSize(300, 300)
        btnClearHistory.addActionListener(StartClearHistory(self))

        btnAbout = JButton("About Privacy Detector...")
        btnAbout.setSize(300, 300)
        btnList.add(btnAbout, BorderLayout.WEST)
        btnAbout.addActionListener(AboutActionListener(self))

        #btnList.add(titleLabel, BorderLayout.NORTH)
        tabPaneController.add(btnList,BorderLayout.CENTER)

        PaneCenter = JPanel(BorderLayout())
        titleLabel = JLabel('HTTP Privacy Detector Extender for Burp Suite')
        titleLabel.setForeground(Color(229, 137, 0))
        titleLabel.setFont(Font('Heading', Font.BOLD, 20))
        titleLabel.setSize(300, 300)
        PaneCenter.add(titleLabel, BorderLayout.NORTH)
        descriptionLabel = JLabel('Privacy Detector is a Burp Suite plugin extracts privacy information from HTTP responses automatically')
        descriptionLabel.setSize(300, 300)
        PaneCenter.add(descriptionLabel, BorderLayout.CENTER)

        tabPaneController.layout.vgap = 20
        PaneCenter.layout.hgap = 20

        tabPaneController.add(PaneCenter,BorderLayout.NORTH)

        PaneStatus = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        statusLabel = JLabel('Status : ')
        self._statusValueLabel = JLabel('Listening...')
        PaneStatus.add(statusLabel)
        PaneStatus.add(self._statusValueLabel)
        tabPaneController.add(PaneStatus,BorderLayout.SOUTH)

        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        #callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return

    
    def getTabCaption(self):
        return "Privacy Detector"
    
    def getUiComponent(self):
        return self._splitpane

    def StartParseFullHTTP(self):
        thread = Thread(StartParseFullHTTPRunnable(self))
        thread.start()
        return

    def StartSendLog(self):
        thread = Thread(StartSendLogRunnable(self))
        thread.start()
        return

    def StartSaveFile(self):
        thread = Thread(StartSaveFileRunnable(self))
        thread.start()
        return

    def StartClearHistory(self):
        dialog = JOptionPane.showConfirmDialog(self._splitpane, "Are you sure want to perform Clear history?","Privacy Detector", JOptionPane.YES_NO_OPTION)
        if dialog == JOptionPane.YES_OPTION:
            self.__stdout.println("StartClearHistory")

            self._lock.acquire()
            #row = self._log.size()
            self._log.clear()
            self.fireTableDataChanged()
            self._lock.release()

            self._responseViewer.setMessage('', False)
            self._currentlyDisplayedItem = ''
            self._logTable.validate()
            self._logTable.repaint()
        return

    def AddLogEntry(self, tool, requestResponse, host, path, matched, piitype, method):
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(tool, requestResponse, host, path, matched, piitype, method))
        self.fireTableRowsInserted(row, row)
        self._lock.release()
        return

    #
    # implement IBurpExtender
    #

    def PIIProcessor(self, toolFlag, responseBody, messageInfo):
        #PII Processor
        try:
            Url = messageInfo.getUrl()
            Method = self._helpers.analyzeRequest(messageInfo).getMethod()
            upart = URL(Url.toString())
            Path = upart.path
            #Host = upart.host
            #Port = upart.port
            httpService = messageInfo.getHttpService()
            Protocol = httpService.getProtocol()
            #Host = httpService.getHost()
            #Port = httpService.getPort()
            #Todo : How to get scheme from URL object?

            HostProtocol = "{}://{}:{}".format(Protocol,upart.host,upart.port)
            IsPIIContaind = False
            for regex in self.__regexs.keys():
                PIIType = self.__regexs.get(regex)
                # Find just one element in the page
                if self.__scanningDepth == 1:
                    matchobj = regex.search(responseBody)
                    if matchobj != None:
                        matched = unicode(matchobj.group().decode('utf-8'),'utf-8')
                        self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                        IsPIIContaind = True
                # Find all elements in the page
                elif self.__scanningDepth != 1:
                    matchObj_iter = regex.finditer(responseBody)
                    if matchObj_iter != None:
                        for matchobj in matchObj_iter:
                            matched = unicode(matchobj.group().decode('utf-8'),'utf-8')
                            self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                            IsPIIContaind = True

        except Exception as e:
            self.__stdout.println(e)

        return IsPIIContaind


    #
    # implement 
    #

    def ParseFullHTTP(self):
        #Parse Full HTTP history
        try:
            httpProxyHistory = self._callbacks.getProxyHistory()

            #logEntry = self._log.get(0)
            #self.__stdout.println(logEntry)

            TotalProxyHistory = len(httpProxyHistory)
            Foundcnt = 0

            for httpProxyItem in httpProxyHistory:
                # Get Response and analyze it
                if httpProxyItem != None and httpProxyItem.getResponse() != None:
                    httpProxyItemResponse = self._helpers.analyzeResponse(httpProxyItem.getResponse())

                    # Do not anything if http status code is one of error type
                    # 301, 302, 307, 401, 402, 403, 404, 405, 406, 408, 411, 500, 502, 503
                    if httpProxyItemResponse.getStatusCode() not in [301, 302, 401, 402, 404, 411, 500]:
                        #Get mime type of HTTP response
                        mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                        if mimeType == '':
                            mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                        #self.__stdout.println("mimeType = {}".format(mimeType))

                        if  (self.__scanningType == 1 and mimeType == 'json') or \
                            (self.__scanningType == 2 and ((mimeType in ["json","xml","text","html"]) or (mimeType == ''))) or \
                            (self.__scanningType == 3 and mimeType not in ["png","gif","css","jpeg","script","image","video","app"]):
                    
                            #Get the response body
                            responseBody = self._helpers.bytesToString(httpProxyItem.getResponse())
                            #self.__stdout.println(responseBody)

                            if httpProxyItemResponse.getBodyOffset() != 0:
                                responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]

                                IsPIIContaind = self.PIIProcessor(4, responseBody, httpProxyItem)
                                if IsPIIContaind == True:
                                    Foundcnt = Foundcnt + 1

            #self.__stdout.println("[+] Found {} PIIs from total {} entries".format(Foundcnt, TotalProxyHistory))
            self._statusValueLabel.setText("[+] Found {} PIIs from total {} entries...".format(Foundcnt, TotalProxyHistory))

        except Exception as e:
            self.__stdout.println(e)

        return

    #
    # implement 
    #

    def SaveFile(self):
        self.__stdout.println("SaveFile func")
        return

    #
    # implement 
    #

    def SendLog(self):
        self.__stdout.println("SendLog func")
        return


    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        try:
            if messageInfo != None:

                #From Proxy
                if toolFlag == 4:

                    # Get Response and analyze it
                    httpProxyItemResponse = self._helpers.analyzeResponse(messageInfo.getResponse())

                    # Do not anything if http status code is one of error type
                    # 301, 302, 307, 401, 402, 403, 404, 405, 406, 408, 411, 500, 502, 503
                    if httpProxyItemResponse.getStatusCode() not in [301, 302, 401, 402, 404, 411, 500]:
                        #Get mime type of HTTP response
                        mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                        if mimeType == '':
                            mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                        #self.__stdout.println("mimeType = {}".format(mimeType))

                        if  (self.__scanningType == 1 and mimeType == 'json') or \
                            (self.__scanningType == 2 and ((mimeType in ["json","xml","text","html"]) or (mimeType == ''))) or \
                            (self.__scanningType == 3 and mimeType not in ["png","gif","css","jpeg","script","image","video","app"]):
                    
                            #Get the response body
                            responseBody = self._helpers.bytesToString(messageInfo.getResponse())

                            if httpProxyItemResponse.getBodyOffset() != 0:
                                responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]

                                #self.__stdout.println(responseBody)
                                self.PIIProcessor(toolFlag, responseBody, messageInfo)

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
        return 7

    def getColumnName(self, columnIndex):

        columnTitle = ["#", "Method", "Host", "Path", "Matched Pattern", "PII Type", "Time"]

        if columnIndex < len(columnTitle):
            return columnTitle[columnIndex]

        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return str(rowIndex)
        elif columnIndex == 1:
            return logEntry._method
        elif columnIndex == 2:
            return logEntry._host
        elif columnIndex == 3:
            return logEntry._path
        elif columnIndex == 4:
            return logEntry._matched
        elif columnIndex == 5:
            return logEntry._piitype
        elif columnIndex == 6:
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
        self._callbacks = extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        #self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)

        try:
            httpProxyItemResponse = self._callbacks.getHelpers().analyzeResponse(logEntry._requestResponse.getResponse())
            if httpProxyItemResponse.getBodyOffset() != 0:

                responseBody = self._callbacks.getHelpers().bytesToString(logEntry._requestResponse.getResponse())
                responseBody = unicode(responseBody[httpProxyItemResponse.getBodyOffset():], 'utf-8').decode('utf-8')

                mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                if mimeType == '':
                    mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                if mimeType == 'json':
                     responseBody = json.dumps(json.loads(responseBody), indent=4, ensure_ascii=False)
                     responseBody = ''.join([
                                    'HTTP/1.1 200 OK\r\n'
                                    'Content-Type: application/json\r\n',
                                    '\r\n',
                                    responseBody])
                   
                     self._extender._responseViewer.setMessage(responseBody.encode('utf-8'), False)
                else:
                     self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
            else:
                self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)

        except Exception as e:
            self.__stdout.println(e)

        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, host, path, matched, piitype, method):
        self._tool = tool
        self._requestResponse = requestResponse
        self._host = host
        self._path = path
        self._matched = matched
        self._piitype = piitype
        self._method = method
        self._time = datetime.now().strftime("%H:%M:%S %m/%d/%Y")


#
# class to run thread Full http history
#

class StartParseFullHTTPRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.println("From StartParseFullHTTPRunnable")

    def run(self):
        #self.__stdout.println("From run StartParseFullHTTPRunnable")
        self._extender._logTable.setAutoCreateRowSorter(False)
        self._extender.ParseFullHTTP()
        self._extender._logTable.setAutoCreateRowSorter(True)
        self._extender._logTable.validate()
        self._extender._logTable.repaint()

#
# class to run thread Full http history
#

class StartSaveFileRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.__stdout.println("From StartSaveFileRunnable")

    def run(self):
        self.__stdout.println("From run StartSaveFileRunnable")
        self._extender.SaveFile()

#
# class to run thread Full http history
#

class StartSendLogRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.__stdout.println("From StartSendLogRunnable")

    def run(self):
        self.__stdout.println("From run StartSendLogRunnable")
        self._extender.SendLog()


#
# class to run thread Save File
#

class StartSaveFile(ActionListener):

    def __init__(self, extender):
        super(StartSaveFile, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.println("StartSaveFile")

    def actionPerformed(self, event):
        self.__stdout.println("actionPerformed")
        self._extender.StartSaveFile()

#
# class to run thread Send Log
#

class StartSendLog(ActionListener):

    def __init__(self, extender):
        super(StartSendLog, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.println("StartSendLog")

    def actionPerformed(self, event):
        self.__stdout.println("actionPerformed")
        self._extender.StartSendLog()

#
# class to run Clear history
#

class StartClearHistory(ActionListener):

    def __init__(self, extender):
        super(StartClearHistory, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.println("StartClearHistory")

    def actionPerformed(self, event):
        #self.__stdout.println("actionPerformed")
        self._extender.StartClearHistory()

#
# class to run thread Full http history
#

class StartParseFullHTTP(ActionListener):

    def __init__(self, extender):
        super(StartParseFullHTTP, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.println("StartParseFullHTTP")

    def actionPerformed(self, event):
        #self.__stdout.println("actionPerformed")
        dialog = JOptionPane.showConfirmDialog(self._extender._splitpane, "Are you sure want to perform ParseFullHistory?","Privacy Detector", JOptionPane.YES_NO_OPTION)
        if dialog == JOptionPane.YES_OPTION:
            if len(self._callbacks.getProxyHistory()) > 0:
                #self.__stdout.println("StartParseFullHTTP")
                self._extender.StartParseFullHTTP()

#
# class to run thread Full http history
#

class AboutActionListener(ActionListener):

    def __init__(self, extender):
        super(AboutActionListener, self).__init__()
        self._extender = extender

    def actionPerformed(self, event):
        JOptionPane.showMessageDialog(self._extender._splitpane, '\n'.join([
            'HTTP Privacy Detector for Burp Suite',
            '',
            'Written by Samuel Koo & Daniel Koo',
            '',
            'GitHub: https://github.com/make0day/privacy_detector',
            '',
            'Mailto: reby7146@me.com or 0day@kakao.com',
            '',
        ]), 'Information - Privacy Detector Burp Plugin 1.0', JOptionPane.INFORMATION_MESSAGE)
