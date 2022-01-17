#!/usr/bin/env python
# -*- coding:utf-8 -*-
##########################################################################################
#                                                                                       #
#                                                                                       #
#                       P r i v a c y D e t e c t o r  P r o j e c t                    #
#                                                                                       #
#                        Github : https://github.com/make0day/privacy_detector          #
#                                                                                       #
#                            Written by Samuel Koo ( 0day@kakao.com )                   #
#                                                                                       #
#                                                and                                    #
#                                                                                       #
#                                       Daniel Koo ( reby7146@me.com )                  #
#                                                                                       #
#########################################################################################
import sys
import os
import json
import re
import time
from datetime import datetime
from threading import Lock
from unicodedata import normalize

from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener, IMessageEditorController, IMessageEditorController
from burp import IScannerCheck, IScanIssue, IScannerListener

from java.awt.event import ActionListener, ItemListener, MouseListener
from java.awt import Component, Color, Font
from java.awt import BorderLayout, FlowLayout, GridLayout
from java.awt import FileDialog
from javax.swing import SwingUtilities, DefaultListModel, ButtonGroup, BorderFactory, ListSelectionModel, DefaultComboBoxModel
from javax.swing import JButton, JTable, JLabel, JList, JProgressBar, JTree, JCheckBox, JComboBox, JFrame
from javax.swing import JPanel, JOptionPane, JScrollPane, JSplitPane, JTabbedPane
from javax.swing.table import AbstractTableModel
from java.lang import Thread, Runnable
from java.lang import *
from java.util import ArrayList, List, Map, HashMap, Hashtable, Vector, Timer, TimerTask
from java.util.regex import *
from java.io import File, PrintWriter, FileWriter, OutputStreamWriter, FileOutputStream, DataOutputStream
from java.io import InputStreamReader, BufferedReader, FileInputStream
from java.net import URL
from jarray import array
from java.security import SecureRandom
from java.nio.file import Files, Paths
from javax.net.ssl import SSLContext, TrustManager, X509TrustManager, HttpsURLConnection

#
# implement IBurpExtender
#

class BurpExtender(IBurpExtender, ITab, IHttpListener, IScannerListener, IScannerCheck, IExtensionStateListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Privacy Detector")

        # if Proxy is enabled than turn off
        callbacks.setProxyInterceptionEnabled(False)

        #set encoding as utf-8
        reload(sys)
        sys.setdefaultencoding('utf-8')

        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)
        #self.__stdout.setCharacterEncoding("UTF-8")  

        self.__stdout.println("Privacy Detector Loaded")
        self.__stdout.println("Coded by Samuel Koo & Daniel Koo")
        self.__stdout.println("Project github : https://github.com/make0day/privacy_detector")

        self.LoadSettings()

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

        tabs.addTab("Dashboard", tabPaneController)
        btnList = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))

        TophitLabel = JLabel('  |  Top list : ')
        btnList.add(TophitLabel)
        chkTophit = JCheckBox("Refresh", True)
        btnList.add(chkTophit)
        chkTophit.addItemListener(chkTophitClicked(self))

        OptionLabel = JLabel('  |  Search : ')
        btnList.add(OptionLabel)
        chkFindAll = JCheckBox("Find All  | ", True)
        btnList.add(chkFindAll)
        chkFindAll.addItemListener(chkFindAllClicked(self))

        CrawlLabel = JLabel(' Auto : ')
        btnList.add(CrawlLabel)
        chkCrawlBox = JCheckBox("Use Crawler  | ", True)
        btnList.add(chkCrawlBox)
        chkCrawlBox.addItemListener(chkCrawlBoxClicked(self))

        ScanLabel = JLabel(' Scan : ')
        btnList.add(ScanLabel)
        scanBox = JComboBox()
        vt = Vector()
        vt.add('Quick Scan')
        vt.add('Deep Scan')
        vt.add('Full Scan')
        scanBox.setModel(DefaultComboBoxModel(vt))
        btnList.add(scanBox)
        scanBox.addItemListener(scanBoxClicked(self))

        btnParseFullHTTP = JButton("Parse full history")
        btnList.add(btnParseFullHTTP)
        btnParseFullHTTP.setSize(300, 300)
        btnParseFullHTTP.addActionListener(StartParseFullHTTP(self))

        btnClearHistory = JButton("Clear history")
        btnList.add(btnClearHistory)
        btnClearHistory.setSize(300, 300)
        btnClearHistory.addActionListener(StartClearHistory(self))

        btnSaveFile = JButton("Save as .csv file")
        btnList.add(btnSaveFile,BorderLayout.SOUTH)
        btnSaveFile.setSize(300, 300)
        btnSaveFile.addActionListener(StartSaveFile(self))

        btnSendLog = JButton("Send Splunk event")
        btnList.add(btnSendLog)
        btnSendLog.setSize(300, 300)
        btnSendLog.addActionListener(StartSendLog(self))

        btnAbout = JButton("About...")
        btnAbout.setSize(300, 300)
        btnList.add(btnAbout)
        btnAbout.addActionListener(AboutActionListener(self))

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
        AuthorLabel = JLabel('Status : Listening...')
        AuthorLabel.setFont(Font('Heading', Font.BOLD, 15))
        AuthorLabel.setSize(300, 300)
        PaneCenter.add(AuthorLabel, BorderLayout.EAST)

        tabPaneController.layout.vgap = 20
        PaneCenter.layout.hgap = 20

        self._tabController = tabPaneController
        self._topHitTable = HashMap()
        self._HitTablelock = Lock()
        self._stopThread = False

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
        
        # register ourselves's handlers
        #callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        callbacks.registerExtensionStateListener(self)
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
        self._LogThread = Thread(StartSendLogRunnable(self))
        self._LogThread.start()
        return

    #
    # 
    #

    def StartSaveFile(self):
        thread = Thread(StartSaveFileRunnable(self))
        thread.start()
        return

    def extensionUnloaded(self):
        self._callbacks.printOutput("Privacy Detector unloaded")
        self._stopThread = True
        return

    #
    # 
    #

    def StartClearHistory(self):
        try:
            self._lock.acquire()
            self._log.clear()
            self.fireTableDataChanged()
            self._lock.release()

            self._HitTablelock.acquire()
            self._topHitTable.clear()
            self._topHitMap.getModel().removeAllElements()
            self._HitTablelock.release()

            self._topHitTable.validate()
            self._topHitTable.repaint()

            self._responseViewer.setMessage('', False)
            self._currentlyDisplayedItem = ''
            self._logTable.validate()
            self._logTable.repaint()
        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # 
    #


    def LoadSettings(self):

        try:
            self.__stdout.println("[+] Load extension Settings...")
            
            # 1 = Json Only Scan, 2 = Json,XML,Text,HTML Scan, 3 = Full Scan (Except images)
            self._scanningType = int(self._callbacks.loadExtensionSetting("SearchType"))
            if self._scanningType == None:
                self._callbacks.saveExtensionSetting("SearchType", "1")
                self._scanningType = 1
            self.__stdout.println("[+] Current Scanning Mime Type  option: {}".format(self._scanningType))

            # 1 = Find one item from the page, 1 > = Find all items
            self._scanningDepth = int(self._callbacks.loadExtensionSetting("ScanningDepth"))
            if self._scanningDepth == None:
                self._callbacks.saveExtensionSetting("ScanningDepth", "2")
                self._scanningDepth = 2
            self.__stdout.println("[+] Current Scanning Depth option : {}".format(self._scanningDepth))
                      
            # 1 = Do not update top list, 2  = Update top list
            self._updateTopList = int(self._callbacks.loadExtensionSetting("RefreshTopList"))
            if self._updateTopList == None:
                self._callbacks.saveExtensionSetting("RefreshTopList", "2")
                self._updateTopList = 2
            self.__stdout.println("[+] Refresh top Hit List option : {}".format(self._updateTopList))

            # 1 = Do not call SpiderMan, 2  = Call SpiderMan
            self._callSpiderMan = int(self._callbacks.loadExtensionSetting("UseAutoCrawler"))
            if self._callSpiderMan == None:
                self._callbacks.saveExtensionSetting("UseAutoCrawler", "2")
                self._callSpiderMan = 2
            self.__stdout.println("[+] Use Auto Crawwer option : {}".format(self._callSpiderMan))
            
            self._callSpiderMan = 2

            # 1 = Do not send log to the Splunk server, 2 = Send log to the Splunk server asynchronously
            self._autoSendLogToSplunk = int(self._callbacks.loadExtensionSetting("SplunkAutoSend"))
            if self._autoSendLogToSplunk == None:
                self._callbacks.saveExtensionSetting("SplunkAutoSend", "2")
                self._autoSendLogToSplunk = 2
            # Every 5 Mins
            self._splunkSleep = int(self._callbacks.loadExtensionSetting("SplunkSleep"))
            if self._splunkSleep == None:
                self._callbacks.saveExtensionSetting("SplunkSleep", "5")
                self._splunkSleep = 5

            # Splunk host
            self._splunkHost = self._callbacks.loadExtensionSetting("SplunkHost")
            if self._splunkHost == None:
                self._callbacks.saveExtensionSetting("SplunkHost", "splunklogserver.com")
                self._splunkHost = 'splunklogserver.com'

            # Your splunk auth token
            self._splunkAuthKey = self._callbacks.loadExtensionSetting("SplunkToken")
            if self._splunkAuthKey == None:
                self._callbacks.saveExtensionSetting("SplunkToken", "pleasefillyoursplunktoken")
                self._splunkAuthKey = 'pleasefillyoursplunktoken'

            #self._callbacks.loadExtensionSetting()
            self.__stdout.println("[+] Splulk log options : {} {} {}".format(self._autoSendLogToSplunk, self._splunkSleep, self._splunkHost, self._splunkAuthKey))


            privacydetectorcfgPath = ''.join([os.path.abspath(os.getcwd()), '/privacy_detector.json'])
            self.__stdout.println("[+] Load configuration file : {}".format(privacydetectorcfgPath))
            if os.path.exists(privacydetectorcfgPath):
                with open('./privacy_detector.json', 'r') as cfg_handle:
                    parsed = json.dumps(json.load(cfg_handle))
                    self._callbacks.loadConfigFromJson(parsed)
            else:
                urlStream = URL('https://raw.githubusercontent.com/make0day/privacy_detector/main/privacy_detector.json').openStream()
                if urlStream != None:
                    downloadedConfig = self._helpers.bytesToString(urlStream.readAllBytes())
                    downloadedConfig = normalize('NFC', downloadedConfig)
                    downloadedConfig = unicode(downloadedConfig, 'utf-8').decode('utf-8')
                    outStream = OutputStreamWriter(FileOutputStream(privacydetectorcfgPath), 'UTF-8')
                    outStream.write(unicode(downloadedConfig))
                    if outStream != None:
                        outStream.close()
                    if downloadedConfig != None:
                        urlStream.close()
                    parsed = json.dumps(json.loads(downloadedConfig))
                    self._callbacks.loadConfigFromJson(parsed)
            self.__stdout.println("[+] Configuration loaded")


        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # Precompile Regex rulesets
    #
    def PrecompilePIIRuleSets(self, patternFile):

        try:
            #precompile regex patterns for better performance
            self.__stdout.println('[+] Precompile Rulesets...')
            self.__regexs = dict()
           
            for pattern in patternFile['patterns']:
                if pattern['use'] == True:
                    expression = normalize('NFC', pattern['expression'])
                    self.__regexs[(re.compile(expression))] = pattern['type']
                    self.__stdout.println(pattern['description'])
            self.__stdout.println('[+] Precompile done')

        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # Load Ruleset file
    #

    def LoadRulesetFile(self):

        patternFile = ''
        keys = ''
        try:
            #Loads patterns file
            patterFilePath = ''.join([os.path.abspath(os.getcwd()), '/patterns.json'])
            if os.path.exists(patterFilePath):
                #f = open(patterFilePath, "r")
                self.__stdout.println('[+] Load pattern file in local path = {}/patterns.json'.format(os.path.abspath(os.getcwd())))
                keys = self._helpers.bytesToString(Files.readAllBytes(Paths.get(patterFilePath)))
                keys = unicode(keys, 'utf-8').decode('utf-8')
            else:
                self.__stdout.println('[-] Pattern file not exist in the local path, download a new one')
                urlStream = URL('https://raw.githubusercontent.com/make0day/privacy_detector/main/patterns.json').openStream()
                if urlStream != None:
                    downloadedPattern = self._helpers.bytesToString(urlStream.readAllBytes())
                    downloadedPattern = normalize('NFC', downloadedPattern)
                    downloadedPattern = unicode(downloadedPattern, 'utf-8').decode('utf-8')
                    #self.__stdout.println(downloadedPattern)
                    outStream = OutputStreamWriter(FileOutputStream(patterFilePath), 'UTF-8')
                    outStream.write(unicode(downloadedPattern))

                    keys = downloadedPattern

                    if outStream != None:
                        outStream.close()
                    if downloadedPattern != None:
                        urlStream.close()
                        self.__stdout.println('[+] Downloaded')
                else:
                    #Possible?
                    self.__stdout.println('[-] File download error happend')

            self.__stdout.println('[+] Pattern file loaded')

            patternFile = json.loads(keys)

        except Exception as e:
            self.__stdout.println(e)

        return patternFile

    #
    # implement IBurpExtender
    #

    def PIIProcessor(self, toolFlag, responseBody, messageInfo):
        #PII Processor
        IsPIIContaind = False

        try:
            Url = messageInfo.getUrl()
            Method = self._helpers.analyzeRequest(messageInfo).getMethod()
            upart = URL(Url.toString())
            Path = upart.path
            httpService = messageInfo.getHttpService()
            Protocol = httpService.getProtocol()
            #Host = httpService.getHost()
            #Port = httpService.getPort()

            #Todo : How to get scheme from URL object?
            HostProtocol = "{}://{}:{}".format(Protocol,upart.host,upart.port)
            responseBody = normalize('NFC', responseBody).decode('utf-8')
            #self.__stdout.println(responseBody)
            for regex in self.__regexs.keys():
                PIIType = self.__regexs.get(regex)
                # Find just one element in the page
                if self._scanningDepth == 1:
                    matchobj = regex.search(responseBody)
                    if matchobj != None:
                        if matchobj.group('dual5651') != None and matchobj.group('dual5651') != '':
                            matched = matchobj.group('dual5651')
                            row = self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                            #Todo check case
                            self.AddHitEntry(HostProtocol, Path, PIIType, Method, row)
                            IsPIIContaind = True
                        #else:
                            #useless
                            #self.__stdout.println("[-] error in PIIProcessor matchObj group(0) == None")

                # Find all elements in the page
                elif self._scanningDepth == 2:
                    matchObj_iter = regex.finditer(responseBody)
                    if matchObj_iter != None:
                        for matchobj in matchObj_iter:
                            if matchobj.group('dual5651') != None and matchobj.group('dual5651') != '':
                                matched = matchobj.group('dual5651')
                                #self.__stdout.println(matched)
                                row = self.AddLogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), HostProtocol, Path, matched, PIIType, Method)
                                #Todo check case
                                self.AddHitEntry(HostProtocol, Path, PIIType, Method, row)
                                IsPIIContaind = True
                            #else:
                                #useless
                                #self.__stdout.println("[-] error in PIIProcessor matchObj group(0) == None")

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

                        if  (self._scanningType == 1 and mimeType == 'json') or \
                            (self._scanningType == 2 and ((mimeType in ["json","xml","text","html"]) or (mimeType == ''))) or \
                            (self._scanningType == 3 and mimeType not in ["png","gif","css","jpeg","script","image","video","app"]):
                    
                            #Get the response body
                            responseBody = self._helpers.bytesToString(httpProxyItem.getResponse()) #.decode('utf-8')

                            if httpProxyItemResponse.getBodyOffset() != 0:
                                responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]
                            else:
                                self.__stdout.println("[-] getBodyOffset == 0")

                            IsPIIContaind = self.PIIProcessor(4, responseBody, httpProxyItem)
                            if IsPIIContaind == True:
                                Foundcnt = Foundcnt + 1
                        #else:
                            #Possible?
                            #self.__stdout.println("[-] Scan type != none of 1-3")

        except Exception as e:
            self.__stdout.println(e)

        return

    #
    # implement Save log
    #

    def SaveFile(self):

        try:

            ancestor = SwingUtilities.getWindowAncestor(self._splitpane)
            saveDialog = FileDialog(ancestor, "Privacy Detector - Save Log", FileDialog.SAVE)
            saveDialog.setDirectory(os.path.abspath(os.getcwd()))
            saveDialog.setVisible(True)
            dir = saveDialog.getDirectory()
            file = saveDialog.getFile()

            if file.lower().endswith('.csv') == False:
                pos = file.rfind('.')
                if pos > 0 and pos < (len(file) - 1):
                    file = file[:pos]

                file = ''.join([file,'.csv'])


            fullpath = ''.join([dir,file])
            outstream = OutputStreamWriter(FileOutputStream(fullpath), 'UTF-8')

            outstream.write(('Method,Host,Path,Type,Time,Note\n'))
            #self._HitTablelock.acquire()
            for key in self._topHitTable.keySet():
                line = self._topHitTable.get(key)
                outstream.write(unicode("{},{},{},{},{},Hit={}\n".format(line._method,line._host,line._path,line._piitype,line._time,line._hit), 'utf-8'))
            #self._HitTablelock.release()

            #self._lock.acquire()
            for line in self._log:
                outstream.write(unicode("{},{},{},{},{},Matched={}\n".format(line._method,line._host,line._path,line._piitype,line._time,line._matched),'utf-8'))

            #self._lock.release()

            outstream.close()

            JOptionPane.showMessageDialog(self._splitpane, 'Log saved : {}'.format(fullpath))

        except Exception as e:
            self.__stdout.println(e)

        return

    #
    # implement 
    #


    def jsonLogGeneration(self):

        jsonResult = {'event':[]}

        try:

            for key in self._topHitTable.keySet():
                line = self._topHitTable.get(key)

                data = {'method' : line._method, \
                      'url' : ''.join([line._host,line._path]),\
                      'type' : line._piitype}

                jsonResult['event'].append(data)


            for line in self._log:
                data = {'method' : line._method, \
                        'url' : ''.join([line._host,line._path]), \
                        'type' : line._piitype}

                jsonResult['event'].append(data)

        except Exception as e:
            self.__stdout.println(e)

        return jsonResult

    #
    # implement 
    #

    def SendLog(self):

        try:

            class TrustDualX509Manager(X509TrustManager):
                def __init__(self, extender):
                    super(TrustDualX509Manager, self).__init__()
                    self._extender = extender
                    self._callbacks = self._extender._callbacks
                    return None

                def checkClientTrusted(self, chain, auth):
                    pass

                def checkServerTrusted(self, chain, auth):
                    pass

                def getAcceptedIssuers(self):
                    return None

            data = {'sourcetype' : 'burp_redteam', \
                      'time' : str(int(round(time.time() * 1000))),
                      'event' : self.jsonLogGeneration()}

            jsonParam = json.dumps(data, ensure_ascii=False, sort_keys=False)

            splunkUrl = URL(''.join(["https://",self._splunkHost,"/services/collector/event"]))
            conn = splunkUrl.openConnection()

            conn.setDoOutput(True)
            conn.setUseCaches(False)
            conn.setRequestMethod("POST")
            conn.setRequestProperty("User-Agent", "Privacy Detector")
            conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8")
            conn.setRequestProperty("Authorization", ''.join(["Splunk ",self._splunkAuthKey]))

            ctx = SSLContext.getInstance("SSL")
            ctx.init(None, array([TrustDualX509Manager(self)], TrustManager), SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory())
            conn.connect()
            conn.setInstanceFollowRedirects(True)

            outStream = DataOutputStream(conn.getOutputStream())
            #self.__stdout.println("Write Data = {}".format(param))
            outStream.writeBytes(unicode(jsonParam, 'utf-8'))

            if conn.getResponseCode() == HttpsURLConnection.HTTP_OK:
                inputStream = conn.getInputStream()
            else:
                inputStream = conn.getErrorStream()

            reader = BufferedReader(InputStreamReader(inputStream))
            if reader != None:
                serverResponse = self._helpers.bytesToString(reader.readLine())
            if serverResponse != None:
                self.__stdout.println("[+] Send log to Splunk server successfully")

            reader.close()
            conn.disconnect()

            outStream.flush()
            outStream.close()

        except Exception as e:
            self.__stdout.println(e)
        return

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            if toolFlag == 8 or toolFlag == 16:
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                self.__stdout.println("[Request from scanner] {}".format(url))
            return
        
        try:
            if messageInfo != None:

                #From TOOL_PROXY=4 or From TOOL_SCANNER=16 or TOOL_SPIDER
                if toolFlag == 4 or toolFlag == 16 or toolFlag == 8:

                    # Get Response and analyze it
                    httpProxyItemResponse = self._helpers.analyzeResponse(messageInfo.getResponse())

                    # Do not anything if http status code is one of error type
                    # 301, 302, 307, 401, 402, 403, 404, 405, 406, 408, 411, 500, 502, 503
                    if httpProxyItemResponse.getStatusCode() not in [301, 302, 401, 402, 404, 411, 500]:
                        #Get mime type of HTTP response
                        mimeType = httpProxyItemResponse.getStatedMimeType().lower()
                        if mimeType == '':
                            mimeType = httpProxyItemResponse.getInferredMimeType().lower()

                        if  (self._scanningType == 1 and mimeType == 'json') or \
                            (self._scanningType == 2 and ((mimeType in ["json","xml","text","html"]) or (mimeType == ''))) or \
                            (self._scanningType == 3 and mimeType not in ["png","gif","css","jpeg","script","image","video","app"]):
                    
                            #Get the response body
                            responseBody = self._helpers.bytesToString(messageInfo.getResponse()) #.decode('utf-8')

                            if httpProxyItemResponse.getBodyOffset() != 0:
                                responseBody = responseBody[httpProxyItemResponse.getBodyOffset():]
                            else:
                                #Possible?
                                self.__stdout.println("[-] getBodyOffset == 0")

                            self.PIIProcessor(toolFlag, responseBody, messageInfo)
                else:
                    return
                    #if toolFlag == 8 or toolFlag == 16:
                        #url = self._helpers.analyzeRequest(messageInfo).getUrl()
                        #self.__stdout.println("hello from response flag = {} url = {}".format(toolFlag, url))


        except Exception as e:
            self.__stdout.println(e)

        return

    #
    #
    #

    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        #matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)
        #if (len(matches) == 0):
        #    return None

        self.__stdout.println("Hello from doPassiveScan")

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "CMS Info Leakage",
            "The response contains the string: " + GREP_STRING,
            "Information")]

    #
    #
    #

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point

        self.__stdout.println("Hello from doActionScan")

        checkRequest = insertionPoint.buildRequest(INJ_TEST)
        checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

        # look for matches of our active check grep string
        #matches = self._get_matches(checkRequestResponse.getResponse(), INJ_ERROR_BYTES)
        #if len(matches) == 0:
        #    return None

        # get the offsets of the payload within the request, for in-UI highlighting
        #requestHighlights = [insertionPoint.getPayloadOffsets(INJ_TEST)]

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
            "Pipe injection",
            "Submitting a pipe character returned the string: " + INJ_ERROR,
            "High")]

    #
    #
    #

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            self.__stdout.println("[-] already in Issue")
            return -1

        return 0

    #
    #
    #


    def amazingSpiderMan(self, host, path):

        url = ''

        url = ''.join([host, '/'])

        self.__stdout.println(''.join(['Maryjane : Please help me, Spider man!! ', url]))
        maryJane = URL(url)
        if self._callbacks.isInScope(maryJane) == False:
            self._callbacks.includeInScope(maryJane)
            self._callbacks.sendToSpider(maryJane)
        else:
            self.__stdout.println("[-] She's not Maryjane :(")

        return
    

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

            if self._updateTopList == 1:
                if row == None:
                    return
                else: 
                    if self._callSpiderMan == 2:
                        self.amazingSpiderMan(host, path)
                    else:
                        return
            else:

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

                TopHitList = []
                for i in self._topHitTable.keySet():
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
                            if self._callSpiderMan == 2:
                                self.amazingSpiderMan(host, path)
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

        try:
            httpProxyItemResponse = self._callbacks.getHelpers().analyzeResponse(logEntry._requestResponse.getResponse())
            if httpProxyItemResponse.getBodyOffset() != 0:

                responseBody = self._callbacks.getHelpers().bytesToString(logEntry._requestResponse.getResponse())
                responseBody = responseBody = normalize('NFC', responseBody[httpProxyItemResponse.getBodyOffset():]).decode('utf-8')

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
        self._time = datetime.now().strftime("%H:%M:%S %m/%d/%Y")

#
# class to run thread Full http history
#

class StartParseFullHTTPRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def run(self):
        self._extender._logTable.setAutoCreateRowSorter(False)
        self._extender.ParseFullHTTP()
        self._extender._logTable.setAutoCreateRowSorter(True)
        self._extender._logTable.validate()
        self._extender._logTable.repaint()
        return
#
# class to run thread Full http history
#

class StartSaveFileRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def run(self):
        self._extender.SaveFile()
        return
#
# class to run thread Full http history
#

class StartSendLogRunnable(Runnable):

    def __init__(self, extender):
        self._extender = extender
        self._callbacks = self._extender._callbacks
        self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def run(self):
        if self._extender._splunkHost == '' or self._extender._splunkAuthKey == '':
            self.__stdout.println('[-] SplunkHost or Splunk auth key is null :(')
        else: 
            if self._extender._autoSendLogToSplunk == 2:
                while self._extender._autoSendLogToSplunk == 2 and self._extender._stopThread == False:
                    self._extender.SendLog()
                    #self.__stdout.println(''.join((["[+] Send log to Splunk server every ", str(self._extender._splunkSleep)," Minutes"])))
                    Thread.sleep(1000 * 60 * self._extender._splunkSleep)
            else:
                self._extender.SendLog()
        return

#
# class to run thread Save File
#

class StartSaveFile(ActionListener):

    def __init__(self, extender):
        super(StartSaveFile, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def actionPerformed(self, event):
        self._extender.StartSaveFile()
        return
#
# class to run thread Send Log
#

class StartSendLog(ActionListener):

    def __init__(self, extender):
        super(StartSendLog, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def actionPerformed(self, event):
        self._extender.StartSendLog()
        return
#
# class to run Clear history
#

class StartClearHistory(ActionListener):

    def __init__(self, extender):
        super(StartClearHistory, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def actionPerformed(self, event):
        self._extender.StartClearHistory()
        return
#
# class to run thread Full http history
#

class StartParseFullHTTP(ActionListener):

    def __init__(self, extender):
        super(StartParseFullHTTP, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def actionPerformed(self, event):
        dialog = JOptionPane.showConfirmDialog(self._extender._splitpane, "Are you sure want to perform ParseFullHistory?","Privacy Detector", JOptionPane.YES_NO_OPTION)
        if dialog == JOptionPane.YES_OPTION:
            if len(self._callbacks.getProxyHistory()) > 0:
                self._extender.StartParseFullHTTP()
        return

#
# class to handle check box
#

class chkFindAllClicked(ItemListener):

    def __init__(self, extender):
        super(chkFindAllClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        if ItemEvent.getStateChange()==1:
            if self._extender._scanningDepth == 2:
                self._extender._scanningDepth = 1
            else:
                self._extender._scanningDepth = 2
            self._callbacks.saveExtensionSetting("ScanningDepth", str(self._extender._scanningDepth))
        else:
            self._extender._scanningDepth = 1
        return

#
# class to handle check box
#

class chkCrawlBoxClicked(ItemListener):

    def __init__(self, extender):
        super(chkCrawlBoxClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        if ItemEvent.getStateChange()==1:
            if self._extender._callSpiderMan == 2:
                self._extender._callSpiderMan = 1
            else:
                self._extender._callSpiderMan = 2
            self._callbacks.saveExtensionSetting("UseAutoCrawler", str(self._extender._callSpiderMan))
        else:
            self._extender._callSpiderMan = 1
        return


#
# class to scan option
#

class scanBoxClicked(ItemListener):

    def __init__(self, extender):
        super(scanBoxClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
       # self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        if ItemEvent.getStateChange()==1:
            self._extender._scanningType = 1 + ItemEvent.getSource().getSelectedIndex()
            self._callbacks.saveExtensionSetting("SearchType", str(self._extender._scanningType))
            #self.__stdout.println("[+] Scan Type Option Channged = {}".format(self._extender._scanningType))
        return

#
# class to scan option
#

class chkTophitClicked(ItemListener):

    def __init__(self, extender):
        super(chkTophitClicked, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    def itemStateChanged(self, ItemEvent):
        if ItemEvent.getStateChange()==1:
            if self._extender._updateTopList == 1:
                self._extender._updateTopList = 2
                #self._extender._topHitLogger.add(self._extender._topHitMap)
            else: 
                self._extender._updateTopList = 1
                #self._extender._topHitLogger.remove(self._extender._topHitMap)
            self._callbacks.saveExtensionSetting("RefreshTopList", str(self._extender._updateTopList))
        else:
            self._extender._updateTopList = 1
        #self.__stdout.println("[+] Top Hit Option Channged = {}".format(self._extender._updateTopList))
        return
#
# class to handle top list event
#

class tableEventHandler(MouseListener):

    def __init__(self, extender):
        super(tableEventHandler, self).__init__()
        self._extender = extender
        self._callbacks = self._extender._callbacks
        #self.__stdout = PrintWriter(self._callbacks.getStdout(), True)

    #
    # 
    #

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
        return

    #
    # 
    #

    def mouseEntered(self, MoustEvent):
        return

    #
    # 
    #

    def mouseExited(self, MoustEvent):
        return

    #
    # 
    #

    def mousePressed(self, MoustEvent):
        return

    #
    # 
    #

    def mouseReleased(self, MoustEvent):
        return

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
        return
#
# class implementing IScanIssue to hold our custom scan issue details
#

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
#
# EOF
#
    