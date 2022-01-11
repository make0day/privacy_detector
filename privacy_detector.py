#!/usr/bin/env python
# -*- coding:utf-8 -*-
##########################################################################################
#                                                                                       #
#                                                                                       #
#                       P r i v a c y D e t e c t o r  P r o j e c t                    #
#                                                                                       #
#                        Github : https://github.com/make0day/privacy_detector          #
#                                                                                       #
#                        Written by Samuel Koo ( 0day@kakao.com )                       #
#                                                                                       #
#                                       and                                             #
#                                                                                       #
#                                 Daniel Koo ( reby7146@me.com )                        #
#                                                                                       #
#########################################################################################
import sys
import os
import json
import re
from datetime import datetime
from threading import Lock
from unicodedata import normalize

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IMessageEditorController

from java.awt.event import ActionListener, ItemListener, MouseListener
from java.awt import Component, Color, Font
from java.awt import BorderLayout, FlowLayout, GridLayout
from javax.swing import SwingUtilities, DefaultListModel, ButtonGroup, BorderFactory, ListSelectionModel, DefaultComboBoxModel
from javax.swing import JButton, JTable, JLabel, JList, JProgressBar, JTree, JCheckBox, JComboBox
from javax.swing import JPanel, JOptionPane, JScrollPane, JSplitPane, JTabbedPane
from javax.swing.table import AbstractTableModel
from java.lang import Thread, Runnable
from java.lang import *
from java.util import ArrayList, List, Map, HashMap, Hashtable, Vector
from java.util.regex import *
from java.io import PrintWriter
from java.net import URL
from java.nio.file import Files

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
            self.__stdout.println('[+] Precompile Rulesets')
            self.__regexs = dict()
           
            for pattern in patternFile['patterns']:
                if pattern['use'] == True:
                    expression = normalize('NFC', unicode(pattern['expression'])) #.decode('utf-8','ignore')
                    #self.__stdout.println(expression)
                    self.__regexs[(re.compile(expression.encode('utf-8')))] = pattern['type']

        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # Load Ruleset file
    #
    def LoadRulesetFile(self):
        f = None
        patternFile = ''
        keys = ''
        try:
            #Loads patterns file
            if os.path.exists("./patterns.json"):
                f = open("./patterns.json", "r")
                self.__stdout.println('[+] Load pattern file in local path')
                keys = f.read()
                #self.__stdout.println(keys)
            else:
                self.__stdout.println('[-] Pattern file not exist in the local path, download a new one')
                InputStream = URL('https://raw.githubusercontent.com/make0day/privacy_detector/main/patterns.json').openStream()
                if InputStream != None:
                    f = open("./patterns.json", "w+")
                    downloadedPattern = self._helpers.bytesToString(InputStream.readAllBytes())
                    downloadedPattern = normalize('NFC', downloadedPattern).encode('utf-8','ignore')
                    f.write(downloadedPattern)
                    keys = downloadedPattern
                    #self.__stdout.println(keys)
                    if downloadedPattern != None:
                        self.__stdout.println('[+] Downloaded')
                else:
                    #Possible?
                    self.__stdout.println('[-] File download error happend')

            patternFile = json.loads(keys)
            if f != None:
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

        patternFile = self.LoadRulesetFile()
        self.PrecompilePIIRuleSets(patternFile)
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.5)

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
        self._tabs = tabs
        #self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        
        tabPaneController = JPanel()
        tabPaneController.setLayout(BorderLayout())


        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        #self._splitpane.setRightComponent(self._responseViewer.getComponent())

        tabs.addTab("Options", tabPaneController)
        btnList = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))

        OptionLabel = JLabel('  |  Search option : ')
        btnList.add(OptionLabel)
        chkFindAll = JCheckBox("Find All  | ", True)
        btnList.add(chkFindAll)
        chkFindAll.addItemListener(chkFindAllClicked(self))

        ScanLabel = JLabel(' Scan Type : ')
        btnList.add(ScanLabel)
        scanBox = JComboBox()
        vt = Vector()
        vt.add('Quick Scan')
        vt.add('Deep Scan')
        vt.add('Full Scan')
        scanBox.setModel(DefaultComboBoxModel(vt))
        btnList.add(scanBox)
        scanBox.addItemListener(scanBoxClicked(self))

        btnParseFullHTTP = JButton("Parse Full history")
        btnList.add(btnParseFullHTTP,BorderLayout.NORTH)
        btnParseFullHTTP.setSize(300, 300)
        btnParseFullHTTP.addActionListener(StartParseFullHTTP(self))

        btnSendLog = JButton("Send log to the server")
        btnList.add(btnSendLog,BorderLayout.EAST)
        btnSendLog.setSize(300, 300)
        btnSendLog.addActionListener(StartSendLog(self))

        btnSaveFile = JButton("Save log as a file")
        btnList.add(btnSaveFile,BorderLayout.SOUTH)
        btnSaveFile.setSize(300, 300)
        btnSaveFile.addActionListener(StartSaveFile(self))

        btnClearHistory = JButton("Clear history")
        btnList.add(btnClearHistory,BorderLayout.CENTER)
        btnClearHistory.setSize(300, 300)
        btnClearHistory.addActionListener(StartClearHistory(self))

        btnAbout = JButton("About Privacy Detector...")
        btnAbout.setSize(300, 300)
        btnList.add(btnAbout)
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
        AuthorLabel = JLabel('Coded by dual5651')
        AuthorLabel.setFont(Font('Heading', Font.BOLD, 15))
        AuthorLabel.setSize(300, 300)
        PaneCenter.add(AuthorLabel, BorderLayout.EAST)

        tabPaneController.layout.vgap = 20
        PaneCenter.layout.hgap = 20

        self._tabController = tabPaneController
        self._topHitTable = HashMap()
        self._HitTablelock = Lock()

        self._topHitMap = JList(Vector(self._topHitTable.keySet()))
        self._topHitMap.setVisible(True)
        self._topHitMap.setVisibleRowCount(10)
        self._topHitMap.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._topHitMap.addMouseListener(tableEventHandler(self))

        self._topHitLogger = JScrollPane(self._topHitMap, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self._topHitLogger.preferredSize = 100, 200
        self._topHitLogger.setBounds(4, 4, 200, 500);
        
        PaneCenter.add(self._topHitLogger, BorderLayout.SOUTH)
        tabPaneController.add(PaneCenter,BorderLayout.NORTH)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(self._topHitMap)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        return

    #
    # 
    #
    
    def getTabCaption(self):
        return "Privacy Detector"
    #
    # 
    #
    
    def getUiComponent(self):
        return self._splitpane
    #
    # 
    #
    
    def StartParseFullHTTP(self):
        thread = Thread(StartParseFullHTTPRunnable(self))
        thread.start()
        return
    #
    # 
    #

    def StartSendLog(self):
        thread = Thread(StartSendLogRunnable(self))
        thread.start()
        return

    #
    # 
    #

    def StartSaveFile(self):
        thread = Thread(StartSaveFileRunnable(self))
        thread.start()
        return

    #
    # 
    #

    def StartClearHistory(self):
        dialog = JOptionPane.showConfirmDialog(self._splitpane, "Are you sure want to perform Clear history?","Privacy Detector", JOptionPane.YES_NO_OPTION)
        if dialog == JOptionPane.YES_OPTION:
            self.__stdout.println("StartClearHistory")

            self._lock.acquire()
            self._log.clear()
            self.fireTableDataChanged()
            self._lock.release()

            self._responseViewer.setMessage('', False)
            self._currentlyDisplayedItem = ''
            self._logTable.validate()
            self._logTable.repaint()
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
            responseBody = normalize('NFC', responseBody)
            for regex in self.__regexs.keys():
                PIIType = self.__regexs.get(regex)
                # Find just one element in the page
                if self.__scanningDepth == 1:
                    matchobj = regex.search(responseBody)
                    if matchobj != None:
                        matched = unicode(matchobj.group().decode('utf-8'))
                        row = self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                        #Todo check case
                        self.AddHitEntry(HostProtocol, Path, PIIType, Method, row)
                        IsPIIContaind = True
                # Find all elements in the page
                elif self.__scanningDepth != 1:
                    matchObj_iter = regex.finditer(responseBody)
                    if matchObj_iter != None:
                        for matchobj in matchObj_iter:
                            matched = unicode(matchobj.group().decode('utf-8'))
                            row = self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                            #Todo check case
                            self.AddHitEntry(HostProtocol, Path, PIIType, Method, row)
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
                                #responseBody = unicode(responseBody[httpProxyItemResponse.getBodyOffset():], 'utf-8').decode('utf-8')
                            else:
                                self.__stdout.println("[-] getBodyOffset == 0")

                            IsPIIContaind = self.PIIProcessor(4, responseBody, httpProxyItem)
                            if IsPIIContaind == True:
                                Foundcnt = Foundcnt + 1

            self.__stdout.println("[+] Found {} PIIs from total {} entries".format(Foundcnt, TotalProxyHistory))

        except Exception as e:
            self.__stdout.println(e)

        return

    #
    # implement 
    #

    def SaveFile(self):
        self.__stdout.println("SaveFile func")
        JOptionPane.showMessageDialog(self._splitpane, 'Not implemented yet')
        return

    #
    # implement 
    #

    def SendLog(self):
        self.__stdout.println("SendLog func")
        JOptionPane.showMessageDialog(self._splitpane, 'Not implemented yet')
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
                                #responseBody = unicode(responseBody[httpProxyItemResponse.getBodyOffset():], 'utf-8').decode('utf-8')
                            else:
                                #Possible?
                                self.__stdout.println("[-] getBodyOffset == 0")

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

    #
    # 
    #

    def getColumnCount(self):
        return 7


    #
    # 
    #

    def getColumnName(self, columnIndex):

        columnTitle = ["#", "Method", "Host", "Path", "Matched", "Type", "Time"]

        if columnIndex < len(columnTitle):
            return columnTitle[columnIndex]

        return ""


    #
    # 
    #

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

    #
    # 
    #

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()


    #
    # 
    #

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


    #
    # 
    #

    def AddLogEntry(self, tool, requestResponse, host, path, matched, piitype, method):
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(tool, requestResponse, host, path, matched, piitype, method))
        self.fireTableRowsInserted(row, row)
        self._lock.release()
        return row

    #
    # 
    #

    def AddHitEntry(self, host, path, piitype, method, linkedrow):
        key = "{}#{}#{}".format(method,host,path)

        try:
            row = self._topHitTable.get(key)
            if row:
                if row._hit >= 1:
                    row._hit = row._hit + 1
                    row._linkedrow = linkedrow
                else:
                    row._hit = 1
            else:
                self._HitTablelock.acquire()
                self._topHitTable.put(key, HitEntry(host, path, piitype, method, linkedrow))
                self._HitTablelock.release()

            CopyModel = DefaultListModel()

            cnt = 0
            TopHitList = []
            for i in self._topHitTable.keySet():
                cnt = cnt + 1
                #Case1
                #Exist in table
                if row:
                    if i == key:
                        TopHitList.append("{} Hits! | URL: {}{} | Method: {}".format(row._hit,row._host,row._path,row._method))
                    else:
                        #Case2
                        #Not updated - do nothing
                        CopyRow = self._topHitTable.get(i)
                        TopHitList.append("{} Hits! | URL: {}{} | Method: {}".format(CopyRow._hit,CopyRow._host,CopyRow._path,CopyRow._method))
                #Case3
                #Not exist in table == New item
                else:
                    row = self._topHitTable.get(key)
                    if row:
                        #Now, Exist (Added new)
                        TopHitList.append("{} Hits! | URL: {}{} | Method: {}".format(row._hit,row._host,row._path,row._method))
                    else:
                        #Error not possible?
                        self.__stdout.println("[-] row zero == 0")

            TopHitList.sort(key=lambda fname: int(fname.split(' ')[0]), reverse=True)

            for item in TopHitList:
                CopyModel.addElement(item)

            self._topHitMap.setModel(CopyModel)

            #self._topHitLogger.validate()
            #self._topHitLogger.repaint()

        except Exception as e:
            self.__stdout.println(e)

        return

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self._callbacks = extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.setModel(extender)

    #
    # 
    #
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        #self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)

        try:
            httpProxyItemResponse = self._callbacks.getHelpers().analyzeResponse(logEntry._requestResponse.getResponse())
            if httpProxyItemResponse.getBodyOffset() != 0:

                responseBody = self._callbacks.getHelpers().bytesToString(logEntry._requestResponse.getResponse())
                responseBody = responseBody = normalize('NFC', responseBody[httpProxyItemResponse.getBodyOffset():]).decode('utf-8','ignore')

                mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                if mimeType == '':
                    mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                if mimeType == 'json':
                     responseBody = json.dumps(json.loads(responseBody), indent=4, ensure_ascii=False)
                     responseBody = ''.join([
                                    'HTTP/1.1 200 OK\r\n'
                                    'Content-Type: application/json; charset=UTF-8\r\n',
                                    '\r\n',
                                    responseBody])
                   
                     self._extender._responseViewer.setMessage(responseBody.encode('utf-8'), False)
                else:
                    content_type = 'Content-Type: text/plain; charset=UTF-8\r\n'
                    for header in re.getHeaders():
                        if header.lower().startswith("content-type:"):
                            content_type = header
                            break

                    responseBody = ''.join([
                                    'HTTP/1.1 200 OK\r\n',
                                    content_type,
                                    '\r\n',
                                    responseBody])

                    self._extender._responseViewer.setMessage(responseBody.encode('utf-8'), False)
            else:
                self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)

        except Exception as e:
            self.__stdout.println(e)
            self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)

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
# class to hold details of each hit entry
#

class HitEntry:
    def __init__(self, host, path, piitype, method, linkedrow):
        self._host = host
        self._path = path
        self._piitype = piitype
        self._method = method
        self._hit = 1
        self._linkedrow = linkedrow
        #self._time = datetime.now().strftime("%H:%M:%S %m/%d/%Y")

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
# class to handle check box
#

class chkFindAllClicked(ItemListener):

    def __init__(self, extender):
        super(chkFindAllClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        #self.__stdout.println("itemStateChanged = {}".format(ItemEvent.getStateChange()==1))
        if ItemEvent.getStateChange()==1:
            self.__scanningDepth = 2
        else:
            self.__scanningDepth = 1
        self.__stdout.println("[+] Find All Channged = {}".format(self.__scanningDepth))

#
# class to scan option
#

class scanBoxClicked(ItemListener):

    def __init__(self, extender):
        super(scanBoxClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        if ItemEvent.getStateChange()==1:
            self.__scanningType = 1 + ItemEvent.getSource().getSelectedIndex()
            self.__stdout.println("[+] Scan Type Channged = {}".format(self.__scanningType))


#
# class to handle top list event
#

class tableEventHandler(MouseListener):

    def __init__(self, extender):
        super(tableEventHandler, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def mouseClicked(self, MoustEvent):
            try:
                key = re.match(r'\d{1,}\sHits!\s\W\sURL:\s(\S{1,})\s\W\sMethod:\s([A-Z]{1,})', MoustEvent.getSource().getSelectedValue())
                upart = URL(key.group(1))
                rkey = "{}#{}".format(key.group(2),key.group(1).replace(upart.path,"#{}".format(upart.path)))
                #self.__stdout.println("[+] MouseClicked = {}".format(rkey))
                row = self._extender._topHitTable.get(rkey)
                if row != None and row._linkedrow != None:
                    self._extender._logTable.changeSelection(row._linkedrow, 0, 0, 0)
                    self._extender._tabs.setSelectedComponent(self._extender._responseViewer.getComponent())

            except Exception as e:
                self.__stdout.println(e)

    def mouseEntered(self, MoustEvent):
        return
            #self.__stdout.println("[+] mouseEntered = ")

    def mouseExited(self, MoustEvent):
        return
            #self.__stdout.println("[+] mouseExited = ")

    def mousePressed(self, MoustEvent):
        return
            #self.__stdout.println("[+] mousePressed = ")

    def mouseReleased(self, MoustEvent):
        return
            #self.__stdout.println("[+] mouseReleased = ")

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

#
# EOF
#
    