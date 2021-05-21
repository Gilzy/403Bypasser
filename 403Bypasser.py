from burp import IBurpExtender, IScanIssue, IScannerCheck

queryPayloadsFile = open('query payloads.txt', "r")
queryPayloadsFromFile = queryPayloadsFile.readlines()

headerPayloadsFile = open('header payloads.txt', "r")
headerPayloadsFromFile = headerPayloadsFile.readlines()

extentionName = "403 Bypasser"

class BurpExtender(IBurpExtender, IScannerCheck):
	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.registerScannerCheck(self)
		callbacks.setExtensionName(extentionName)

		sys.stdout = callbacks.getStdout()
		sys.stderr = callbacks.getStderr()

		return None

	def isInteresting(self, response):
		responseCode = response.getStatusCode()
		if responseCode == 403:
			return True
		else:
			return False

	def findAllCharIndexesInString(self,s, ch):
		return [i for i, ltr in enumerate(s) if ltr == ch]

	def generatePayloads(self, path, payload):
		payloads = []

		#generate payloads before slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + payload + path[i:]
			payloads.append(pathWithPayload)

		#generate payloads after slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads in between slashes
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + "/" + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads at the end of the path
		payloads.append(path + "/" + payload)
		payloads.append(path + "/" + payload + "/")

		return payloads

	def tryBypassWithQueryPayload(self, request, payload, httpService):
		results = []

		requestPath = request.getUrl().getPath()
		payloads = self.generatePayloads(requestPath, payload)

		originalRequest = self.helpers.bytesToString(request.getRequest())
		for pathToTest in payloads:
			newRequest = originalRequest.replace(requestPath, pathToTest)
			newRequestResult = self.callbacks.makeHttpRequest(httpService, newRequest)
			newRequestStatusCode = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getStatusCode())

			if newRequestStatusCode == "200":
				originalRequestUrl = str(request.getUrl())
				vulnerableReuqestUrl = originalRequestUrl.replace(requestPath,pathToTest)
				print "tested path " + pathToTest +". status code: "+ newRequestStatusCode
				results.append("<ul>- " + originalRequestUrl + " => 403<br>" + "  " + vulnerableReuqestUrl.replace(payload, "<b>" + payload + "</b>") + " => " + newRequestStatusCode + "</ul>")

		if len(results) > 0:
			return results
		else:
			return None

	def doPassiveScan(self, baseRequestResponse):
		queryPayloadsResults = []
		headerPayloadsResults = []

		httpService = baseRequestResponse.getHttpService()
		response = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
		if self.isInteresting(response) == False:
			return None

		else:
			#test for query-based issues
			for payload in queryPayloadsFromFile:
				payload = payload.rstrip('\n')
				result = self.tryBypassWithQueryPayload(baseRequestResponse, payload, httpService)
				if result != None:
					queryPayloadsResults += result

			if len(queryPayloadsResults) > 0:
				#get queryPayloadsResults details before returning
				return [CustomScanIssue(
					httpService,
					self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
					[baseRequestResponse],
					"Possible 403 Bypass",
					"".join(queryPayloadsResults),
					"High",
					)]




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
        return "Firm"

    def getIssueBackground(self):
        return extentionName + " sent a request and got 403 response. " + extentionName + " sent another request and got 200 response, this may indicate a misconfiguration on the server side that allows access to forbidden pages."

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