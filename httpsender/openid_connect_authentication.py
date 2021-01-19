#
# To get more background information on how to use this script, go to 
# https://augment1security.com/authentication/how-to-authenticate-with-openid-connect-angular2-spa-zap-part-1/
#

import json
import time
import datetime
import random
import string
import urllib
import org.parosproxy.paros.network.HttpRequestHeader as HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader as HttpHeader
import org.zaproxy.zap.extension.script.ScriptVars as GlobalVariables
import org.parosproxy.paros.network.HttpMessage as HttpMessage
import org.parosproxy.paros.network.HtmlParameter as HtmlParameter
import org.parosproxy.paros.network.HttpSender as HttpSender
import java.net.HttpCookie as HttpCookie
from org.apache.commons.httpclient import URI
from synchronize import make_synchronized
import org.openqa.selenium.By as By
import java.util.concurrent.TimeUnit as TimeUnit
import org.openqa.selenium.firefox.FirefoxDriver as FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions as FirefoxOptions;
import org.openqa.selenium.support.ui.WebDriverWait as WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions as ExpectedConditions;
import org.parosproxy.paros.model.Model as Model
import org.apache.http.client.utils.URLEncodedUtils as URLEncodedUtils
import java.nio.charset.Charset as Charset;
import java.net.URLEncoder as URLEncoder
import java.nio.charset.StandardCharsets as StandardCharsets

APP_ANGULAR_URL = 'http://localhost:8080/app-angular2';
ENCODED_APP_ANGULAR_URL=URLEncoder.encode(APP_ANGULAR_URL, StandardCharsets.UTF_8.toString());
KEYCLOAK_BASE_URL = 'http://localhost:8180/auth';
KEYCLOAK_REALM="master";
USERNAME = "myuser";
PASSWORD = "mypassword";

#constants of cookie names
AUTH_SESSION_ID_LEGACY_COOKIE_NAME="AUTH_SESSION_ID_LEGACY";
KC_RESTART_COOKIE_NAME="KC_RESTART";
KEYCLOAK_IDENTITY_LEGACY_COOKIE_NAME="KEYCLOAK_IDENTITY_LEGACY";
KEYCLOAK_SESSION_LEGACY_COOKIE_NAME="KEYCLOAK_SESSION_LEGACY";
ACCESS_TOKEN_KEY_NAME="ACCESS_TOKEN";
ACCESS_TOKEN_CREATION_TIMESTAMP_KEY_NAME="ACCESS_TOKEN_CREATE_TIMESTAMP";#needs to have a lenght < 30 for a key in GlobalVariables
ACCESS_TOKEN_EXPIRY_IN_SECONDS_KEY_NAME="ACCESS_TOKEN_EXPIRY_IN_SEC";#needs to have a lenght < 30 for a key in GlobalVariables

def sendingRequest(msg, initiator, helper):
    print('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
 
    accessToken = GlobalVariables.getGlobalVar(ACCESS_TOKEN_KEY_NAME);    

    #checking if we already have an access token
    if accessToken is not None:
        print "we have access token, checking if token is valid";
        if tokenHasNotExpired(accessToken) == True:
            print "accessToken in valid";
            setAccessTokenInHttpMessage(accessToken, msg);
            return;
 
    print "token is invalid or there is no token, need to relogin"
    accessToken = refreshAccessToken(helper);
    setAccessTokenInHttpMessage(accessToken, msg);
    return;

# clearing of the variables from GlobalVarialbes
def clearAccessTokenFromGlobalVar():
    GlobalVariables.setGlobalVar(ACCESS_TOKEN_KEY_NAME, None);
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP_KEY_NAME, None);    
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS_KEY_NAME, None);    

# as all 3 variables need to be set at the same time, better to have a function to do that
def setAccessTokenInGlobalVar(accessToken, expiryInSeconds):
    GlobalVariables.setGlobalVar(ACCESS_TOKEN_KEY_NAME, str(accessToken)); 
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP_KEY_NAME, time.time());    
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS_KEY_NAME, expiryInSeconds);

def generateRandomAlphanumericString(length):
    seq = string.letters + string.digits
    return ''.join(random.choice(seq) for _ in xrange(length))

# we have to make this function synchronized as we do not want to have duplicate concurrent attempts to login
@make_synchronized
def refreshAccessToken(helper):
    print "refreshing access token and checking if it has already been refreshed"
    accessToken = GlobalVariables.getGlobalVar(ACCESS_TOKEN_KEY_NAME);    
    if accessToken is not None and tokenHasNotExpired(accessToken) == True:
        print "access token already refreshed, no need to relogin"
        return accessToken;
 
    clearAccessTokenFromGlobalVar();
    accessTokenDict = doLogin(helper);
    setAccessTokenInGlobalVar(accessTokenDict["accessToken"], accessTokenDict["accessTokenExpiryInSeconds"]);

    print "access token refreshed"
    return accessTokenDict["accessToken"];
 
def tokenHasNotExpired(accessToken):
    accessTokenCreationTimestamp = GlobalVariables.getGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP_KEY_NAME);

    #Return the time as a floating point number expressed in seconds since the epoch, in UTC
    currentTime = time.time();
    difference = currentTime - accessTokenCreationTimestamp;
    print "difference in time in seconds:" + str(difference)

    accessTokenExpiryInSeconds = GlobalVariables.getGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS_KEY_NAME);
    if difference > accessTokenExpiryInSeconds:
        print "token has expired"
        return False;

    print "token has NOT expired"
    return True;

def doLogin(helper):
    firefoxOptions = FirefoxOptions()
    firefoxOptions.addArguments("--window-size=1920,1080");
    firefoxOptions.addArguments("--disable-gpu");
    firefoxOptions.addArguments("--disable-extensions");		
    firefoxOptions.addArguments("--proxy-server='direct://'");
    firefoxOptions.addArguments("--proxy-bypass-list=*");
    firefoxOptions.addArguments("--start-maximized");
    firefoxOptions.addArguments("--headless");
    webDriver = FirefoxDriver(firefoxOptions);

    # generate state and nonce
    state = generateRandomAlphanumericString(20);
    nonce = generateRandomAlphanumericString(20);
    print "state:"+state;
    print "nonce:"+nonce;    

    #------------getting login page from keycloak------------
    loginUrl = KEYCLOAK_BASE_URL+"/realms/"+KEYCLOAK_REALM+"/protocol/openid-connect/auth?client_id=app-angular2&redirect_uri="+ENCODED_APP_ANGULAR_URL+"%2F&state="+state+"&nonce="+nonce+"&response_mode=fragment&response_type=code&scope=openid";
    print("loginUrl:"+loginUrl);
    webDriver.get(loginUrl);

    # we wait until the username element is visible
    timeoutInSeconds = 10;
    wait = WebDriverWait(webDriver, timeoutInSeconds); 
    wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));

    loginEle = webDriver.findElement(By.name("username"));
    formEle = webDriver.findElement(By.id("kc-form-login"));

    # gathering all the information to make the next http request
    formActionUrl = formEle.getAttribute("action");
    formBody = "username="+USERNAME+"&password="+PASSWORD+"&credentialId="
    
    authSessionIdLegacyCookieValue = webDriver.manage().getCookieNamed(AUTH_SESSION_ID_LEGACY_COOKIE_NAME).getValue();
    print "authSessionIdLegacyCookieValue: " + authSessionIdLegacyCookieValue;
    kcRestartCookieValue = webDriver.manage().getCookieNamed(KC_RESTART_COOKIE_NAME).getValue();
    print "kcRestartCookieValue: " + kcRestartCookieValue;
    
    authSessionIdLegacyCookie = HttpCookie(AUTH_SESSION_ID_LEGACY_COOKIE_NAME, authSessionIdLegacyCookieValue);
    kcRestartCookie = HttpCookie(KC_RESTART_COOKIE_NAME, kcRestartCookieValue);
    cookies = [authSessionIdLegacyCookie, kcRestartCookie];
    #-----------------------------------------------------

    #------------submitting login credentials to keycloak------------
    returnedMsg = callPost(formActionUrl, formBody, {}, cookies, "application/x-www-form-urlencoded", helper);
    
    keyCloakIdentityLegacyCookieValue = returnedMsg.getResponseHeader().getHeader(KEYCLOAK_IDENTITY_LEGACY_COOKIE_NAME)
    keyCloakSessionLegacyCookieValue = returnedMsg.getResponseHeader().getHeader(KEYCLOAK_SESSION_LEGACY_COOKIE_NAME);

    # we will get a redirect response whose url in the 'location' header we will need to call manually below to get the token
    # we cannot use selenium at this stage as it will do auto redirect and we will miss the information returned by the redirect response
    location = returnedMsg.getResponseHeader().getHeader("Location");
    print "location: " + location;
    codeQueryParamValue = getUrlQueryParamValue(location, "code");
    print("code:" + codeQueryParamValue);
    
    tokenUrl = KEYCLOAK_BASE_URL+"/realms/"+KEYCLOAK_REALM+"/protocol/openid-connect/token"
    formBody = "code="+codeQueryParamValue+"&grant_type=authorization_code&client_id=app-angular2&redirect_uri="+ENCODED_APP_ANGULAR_URL+"%2F";
    keyCloakIdentityLegacyCookie = HttpCookie(KEYCLOAK_IDENTITY_LEGACY_COOKIE_NAME, keyCloakIdentityLegacyCookieValue);
    keyCloakSessionLegacyCookie = HttpCookie(KEYCLOAK_SESSION_LEGACY_COOKIE_NAME, keyCloakSessionLegacyCookieValue);
    cookies = [authSessionIdLegacyCookie, keyCloakIdentityLegacyCookie, keyCloakSessionLegacyCookie];
    #-----------------------------------------------------

    #-----------calling the url in the 'location' header to get the access token-----------
    returnedMsg = callPost(tokenUrl, formBody, {}, cookies, "application/x-www-form-urlencoded", helper);
    
    authenticatedJsonResponseObject = json.loads(str(returnedMsg.getResponseBody()));
    accessToken = authenticatedJsonResponseObject.get("access_token");
    accessTokenExpiryInSeconds = authenticatedJsonResponseObject.get("expires_in");
    print "accessToken:"+str(accessToken);
    print "accessTokenExpiryInSeconds:"+str(accessTokenExpiryInSeconds);
    return dict({"accessToken": accessToken, "accessTokenExpiryInSeconds": accessTokenExpiryInSeconds})
 
# function to set the token in Authorization header in request
def setAccessTokenInHttpMessage(accessToken, msg):
    print "setting token in request"
    msg.getRequestHeader().setHeader("Authorization", "Bearer " + accessToken);

# generic function to make a POST request
def callPost(requestUrl, requestBody, headers, cookies, contentType, helper):
    print "-----start of callPost ("+requestUrl+")-------";
 
    requestUri = URI(requestUrl, False);
    msg = HttpMessage();
    requestHeader = HttpRequestHeader(HttpRequestHeader.POST, requestUri, HttpHeader.HTTP10);
    requestHeader.setHeader("content-type",contentType);

    for name, value in headers.items():
        requestHeader.setHeader(name, value);

    requestHeader.setCookies(cookies)
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    print("Sending POST request header: " + str(requestHeader));
    print("Sending POST request body: " + str(requestBody));
    helper.getHttpSender().sendAndReceive(msg);
    print("\nReceived response status code for authentication request: " + str(msg.getResponseHeader()));
    print("\nResponseBody: " + str(msg.getResponseBody()));
    print("------------------------------------");
    return msg;

# generic function to get the value of a query parameter
def getUrlQueryParamValue(url, paramNameToLookFor):
    urlParams = URLEncodedUtils.parse(url, Charset.forName("UTF-8"));
    for param in urlParams:
        if param.getName() == paramNameToLookFor:
            return param.getValue();
    return None;

# generic function to make a GET request
def callGet(requestUrl, headers, helper):
    requestUri = URI(requestUrl, False);
    print "-----start of callGet-------";
    print "requestUrl:"+requestUrl;
    msg = HttpMessage();
    requestHeader = HttpRequestHeader(HttpRequestHeader.GET, requestUri, HttpHeader.HTTP10);
    msg.setRequestHeader(requestHeader);

    for name, value in headers.items():
        requestHeader.setHeader(name, value);

    print "Sending GET request: " + str(requestHeader);

    helper.getHttpSender().sendAndReceive(msg)
    print "Received response status code for authentication request: " + str(msg.getResponseHeader());
    print("\nResponseBody: " + str(msg.getResponseBody()));
    print "------------------------------------";
    return msg;

# function called for every incoming server response from server (part of httpsender)
def responseReceived(msg, initiator, helper):
    pass