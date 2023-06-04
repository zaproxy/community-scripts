# Version 1.0
# @author RUFFENACH Timothée
# Get OAST burp colaborator.

from javax.swing import JFrame, JPanel, JComboBox, JOptionPane,JFileChooser,JOptionPane
import urllib2
import json
import sys
import base64
import time


global biid

def main():
        global biid 
        biid = getString("what is your biid ?")
         
        # Get number for update info
        update = getNumber(1,3600, "how many time do you want refresh information ?")        

        while True:
                # URL request
                url = "http://polling.oastify.com/burpresults?biid="+biid
        
                # Get response
                response = urllib2.urlopen(url)
                data = response.read()
   
                # analyse response JSON
                json_data = json.loads(data)

                # get json data
                browseJson(json_data)

                # wait
                time.sleep(update)

# find object JSON
def browseJson(obj, path=""):
        if isinstance(obj, dict):
                for key, value in obj.items():
                        newPath = path + "." + key if path else key
                        browseJson(value, newPath)
        elif isinstance(obj, list):
                for index, item in enumerate(obj):
                        newPath = path + "[{}]".format(index)
                        browseJson(item, newPath)
        else:  
                obj = str(obj)
                obj = convertBase64(obj)
                sys.stdout.write("key : {}\n".format(path))
                sys.stdout.write("info : {}\n\n".format(obj))   

# check if string is base64 and convert it
def convertBase64(text):
        # Add padding
        padding = len(text) % 4
        textBase64 = text
        if padding > 0:
                textBase64 += '=' * (4-padding)
        try:
                # Decode string
                textDecode = base64.b64decode(textBase64)
                return textDecode
        except Exception as e:
                if str(e) == 'Incorrect padding':
                        return text
                else:
                        # if not base64, is not decoded
                        return text

def getNumber(min,max,asked):
	number = JOptionPane.showInputDialog(None, asked, "Input", JOptionPane.QUESTION_MESSAGE)
    
	if int(number) >= min and int(number) <= max:
		number = int(number)
		return number
	else:
		JOptionPane.showMessageDialog(None, "Choose number between " +  min  + " to " + max)
		getNumber()


def getString(question):
        stringInput = JOptionPane.showInputDialog(None, question, "Input", JOptionPane.QUESTION_MESSAGE)
        return stringInput 

main()
