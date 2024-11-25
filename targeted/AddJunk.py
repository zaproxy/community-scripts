#This script adds some junk data to the selected request and sends it to a new requester tab
#Script created to work as https://github.com/assetnote/nowafpls
#Written by @5ubterranean_
#If you want to put a Custom Size select "Custom" as the size

import java.awt.event;

import json
import re
from org.parosproxy.paros.view import AbstractFrame
from javax.swing import JLabel
from javax.swing import JMenuBar
from javax.swing import JMenu
from javax.swing import JMenuItem
from javax.swing import JFrame
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JComboBox
requester = control.getExtensionLoader().getExtension("ExtensionRequester")

#Checks generated with IA will check the Content-type header first
def is_json(Ctype, text):
    if "application/json" in Ctype:
        return True
    try:
        json.loads(text)
        return True
    except:
        return False

def is_xml(Ctype, xml_string):
    if "application/xml" in Ctype:
        return True

    if xml_string[0] != "<" or xml_string[-1] != ">":
        return False

    # Remove leading and trailing whitespace
    xml_string = xml_string.strip()
    
    # Check if the string starts with XML declaration (optional)
    xml_declaration_pattern = r'^\s*<\?xml\s+version="1\.0"\s*\?>'
    if re.match(xml_declaration_pattern, xml_string):
        # Remove the XML declaration from the string
        xml_string = re.sub(xml_declaration_pattern, '', xml_string)
    
    # Check for well-formedness
    # A simplistic approach to check if tags are properly nested and closed
    tag_pattern = r'</?([a-zA-Z_][\w.-]*)\s*[^>]*>'
    tags = re.findall(tag_pattern, xml_string)
    
    stack = []
    print(tags)
    #Checks if tag appears twice (open and close), will fail with autoclosing tags
    for tag in tags:
        if tag not in stack:
            stack.append(tag)
        else:
            stack.remove(tag)

    # Check if stack is empty at the end
    print(stack)
    return len(stack) == 0

def is_http_post_form(Ctype, text):
    if "application/x-www-form-urlencoded" in Ctype:
        return True
    # Simple check for key=value pairs. This is a basic check and may not cover all cases.
    return bool(re.match(r'^(?:[^\s=&]+=[^\s=&]+)(?:&[^\s=&]+=[^\s=&]+)*$', text))

def is_multipart_data(Ctype, text):

    if "multipart/form-data" in Ctype:
        return True
    # Check if the text has the typical structure of multipart/form-data
    boundary_pattern = r'--([a-zA-Z0-9]+)'
    parts = text.split('\n')
    
    if len(parts) < 2:
        return False
        
    for part in parts:
        if re.search(boundary_pattern, part):
            return True
    return False

def check_format(Ctype, text):
    if is_json(Ctype, text):
        return "JSON"
    elif is_xml(Ctype, text):
        return "XML"
    elif is_http_post_form(Ctype, text):
        return "POST FORM"
    elif is_multipart_data(Ctype, text):
        return "MULTIPART DATA"

def padXML(HTTPBody, padding):
    padBody =  "<!--" + "a" * (padding - 7) + "-->" + HTTPBody
    return padBody

def padJSON(HTTPBody, padding):
    padBody = '{"junk":"' + "0" * (padding - 10) + '"' + ',' + HTTPBody[1:len(HTTPBody)]
    return padBody

def padFORM(HTTPBody, padding):
    padBody = "a=" + "0" * (padding - 2) + "&" + HTTPBody
    return padBody

def padMultipart(cType, HTTPBody, padding):    
    typeSplit = cType.split(";")
    i = 0
    while i < len(typeSplit):
        if "boundary" in typeSplit[i]:
            boundary = typeSplit[i]
            break
        else:
            i = i + 1
    padBody = "--" + boundary[10:len(boundary)] + "\n" + 'Content-Disposition: form-data; name="junk_data"' + "\n\n" + "0" * (padding - (len(boundary[10:len(boundary)]) + 48)) + "\n\n" + HTTPBody
    return padBody

def invokeWith(msg):
    #Clonning request first to avoid making changes to the original request
    cloned = msg.cloneRequest()
    #Defines values for pop up box
    frame = JFrame("Junk size")
    frame.setLocation(100,100)
    frame.setSize(460,180)
    frame.setLayout(None)
    lbl1 = JLabel("Type: ")
    lbl1.setBounds(60,20,60,20)
    typelist = ["JSON","XML", "POST FORM","MULTIPART DATA"]
    txt1 = JComboBox(typelist)
    txt1.setBounds(130,20,200,20)
    lbl2 = JLabel("Size: ")
    lbl2.setBounds(60,50,60,20)
    choices = ["8 KB","16 KB", "32 KB","64 KB","128 KB","1024 KB","CUSTOM"]
    txt2 = JComboBox(choices)
    txt2.setBounds(130,50,200,20)
    lbl3 = JLabel("Custom: ")
    lbl3.setBounds(60,80,100,20)
    txt3 = JTextField(100)
    txt3.setBounds(130,80,200,20)
        
    def getValues(event):
        #Reading Size for the junk data
        if str(txt2.getSelectedItem()) == "8 KB":
            padSize = 8000
        elif str(txt2.getSelectedItem()) == "16 KB":
            padSize = 16000
        elif str(txt2.getSelectedItem()) == "32 KB":
            padSize = 32000
        elif str(txt2.getSelectedItem()) == "64 KB":
            padSize = 64000
        elif str(txt2.getSelectedItem()) == "128 KB":
            padSize = 128000
        elif str(txt2.getSelectedItem()) == "1024 KB":
            padSize = 1024000
        elif str(txt2.getSelectedItem()) == "CUSTOM":
            padSize = int(txt3.getText())

        #Select content type according to what is selected on the combo box, done in case user changed the type due the autodetect failing
        contentFormat = txt1.getSelectedItem()

        #Create new body with the junk data added        
        if contentFormat == "JSON":
            newBody = padJSON(cloned.getRequestBody().toString(), padSize)
        elif contentFormat == "XML":
            newBody = padXML(cloned.getRequestBody().toString(), padSize)
        elif contentFormat == "POST FORM":
            newBody = padFORM(cloned.getRequestBody().toString(), padSize)
        elif contentFormat == "MULTIPART DATA":
            Ctype = cloned.getRequestHeader().getHeader("Content-Type")
            newBody = padMultipart(Ctype, cloned.getRequestBody().toString(), padSize)
        cloned.setRequestBody(newBody)
        cloned.getRequestHeader().setContentLength(cloned.getRequestBody().length())
        #Sends request to a new requester tab
        requester.newRequesterPane(cloned)
        #Closes pop up box
        frame.dispose()
        
    btn = JButton("Submit", actionPerformed = getValues)
    btn.setBounds(160,110,100,20)        
    frame.add(lbl1)
    frame.add(txt1)
    frame.add(lbl2)
    frame.add(txt2)
    frame.add(lbl3)
    frame.add(txt3)
    frame.add(btn)
    frame.setVisible(True)
    Ctype = cloned.getRequestHeader().getHeader("Content-Type")
    contentFormat = check_format(Ctype, cloned.getRequestBody().toString())
    if contentFormat == "JSON":
        txt1.setSelectedIndex(0)
    elif contentFormat == "XML":
        txt1.setSelectedIndex(1)
    elif contentFormat == "POST FORM":
        txt1.setSelectedIndex(2)
    elif contentFormat == "MULTIPART DATA":
        txt1.setSelectedIndex(3)