# Enhanced Burp Extension for Regex Detection
# Improved output clarity and reduced false positives

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTextArea, JScrollPane, SwingUtilities
import re
import json

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Enhanced Regex Detector")
        callbacks.registerHttpListener(self)
        
        # Load regex patterns from JSON file
        self.patterns = self.load_patterns('C:\Users\d4rk\Documents\json-rules-stable.json')

        # Setup GUI
        self.panel = JPanel()
        self.textArea = JTextArea(30, 80)
        scrollPane = JScrollPane(self.textArea)
        self.panel.add(scrollPane)
        callbacks.addSuiteTab(self)

        self.log("Loaded patterns: {}".format(len(self.patterns)))

    def load_patterns(self, filepath):
        with open(filepath, 'r') as file:
            data = json.load(file)
        patterns = []
        for item in data['patterns']:
            name = item['pattern']['name']
            regex = item['pattern']['regex']
            confidence = item['pattern']['confidence']
            patterns.append({"name": name, "regex": regex, "confidence": confidence})
        return patterns

    def getTabCaption(self):
        return "Regex Detector"

    def getUiComponent(self):
        return self.panel

    def log(self, message):
        SwingUtilities.invokeLater(lambda: self.textArea.append(message + "\n"))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        response = messageInfo.getResponse()
        analyzedResponse = self.helpers.analyzeResponse(response)
        body_offset = analyzedResponse.getBodyOffset()
        response_body = self.helpers.bytesToString(response[body_offset:])
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        url = str(requestInfo.getUrl())

        findings = []

        for pattern in self.patterns:
            matches = re.findall(r'\b' + pattern['regex'] + r'\b', response_body)
            if matches:
                findings.append({"pattern": pattern, "matches": matches})

        if findings:
            log_message = "URL: {}\n".format(url)
            for finding in findings:
                log_message += "Pattern Name: {}\n".format(finding["pattern"]["name"])
                log_message += "Confidence: {}\n".format(finding["pattern"]["confidence"])
                log_message += "Matches: {}\n".format(finding["matches"])
                log_message += "-" * 60 + "\n"

                # Add to Burp issues
                messageInfo.setHighlight("yellow")
                messageInfo.setComment("Detected: {}".format(finding["pattern"]["name"]))

            self.log(log_message)
