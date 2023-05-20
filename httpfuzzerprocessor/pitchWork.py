# Version 1.0
# @author RUFFENACH Timothée
# Script inspired from https://02108124551050482571.googlegroups.com/attach/54c6e34f6fe20/message_processor.js?part=0.1&view=1&vt=ANaJVrEJuACewYorhYYa_zyhyMSug06pmlERCqfYdLsukQBC3OW3LATuXG1WHk_Fw9a0nhexG8ykFDuFgBGYrKAg_pOQ61M36MwC9SOBGvK4KLZn3eDkNzY (dot run on owasp 2.12.0)
# The script fuzz in mode pitchfork.
# To Use : Enable script.
# In fuzzer Add 2 EmptyNull with good number.
# Select two 2 files and launch  the fuzzer.

from java.nio.file import Paths
from javax.swing import JFileChooser
from org.zaproxy.zap.extension.fuzz.payloads.generator import FileStringPayloadGenerator

payloads1 = None
payloads2 = None
init = False

def processMessage(utils, message):
    global payloads1, payloads2, init
    
    if not init:
        initialise()
    
    # Stop if has end of payloads
    if not (payloads1.hasNext() and payloads2.hasNext()):
        utils.stopFuzzer()
        payloads1.close()
        payloads2.close()
        return
        
    # Get the next value of payloas 
    payload1 = payloads1.next().getValue()
    payload2 = payloads2.next().getValue()    

    # Get information of body and replace with payload value
    body = message.getRequestBody().toString()
    body = body.replace(utils.getPaylaods().get(0).getValue(), payload1)
    body = body.replace(utils.getPaylaods().get(1).getValue(), payload2)
    
    # Set payload value to show in Fuzzer
    utils.getPaylaods().set(0, payload1)
    utils.getPaylaods().set(1, payload2)

    # Apply the payload in body
    message.getRequestBody().setBody(body)
    message.getRequestHeader().setContentLength(message.getRequestBody().length())

def processResult(utils, fuzzResult):
    return True

def initialise():
    global payloads1, payloads2, init

    # Choose file1 for first payload
    fileChooser = JFileChooser()
    fileChooser.setMultiSelectionEnabled(True)
    filePath1 = ""
    result = fileChooser.showOpenDialog(None)

    if result == JFileChooser.APPROVE_OPTION:
        selectedFiles = fileChooser.getSelectedFiles()
        for file in selectedFiles:
            filePath1 = file.getAbsolutePath()
            print('The path is :', filePath1)
 
    # Choose file2 for second payload
    fileChooser = JFileChooser()
    fileChooser.setMultiSelectionEnabled(True)
    filePath2 = ""
    result = fileChooser.showOpenDialog(None)

    if result == JFileChooser.APPROVE_OPTION:
        selectedFiles = fileChooser.getSelectedFiles()
        for file in selectedFiles:
            filePath2 = file.getAbsolutePath()
            print('The path is :', filePath2)
            
    # Setup path
    file1 = Paths.get(filePath1)
    file2 = Paths.get(filePath2)
    
    # Get payload in file to var payloads
    payloads1 = FileStringPayloadGenerator(file1).iterator()
    payloads2 = FileStringPayloadGenerator(file2).iterator()
    init = True
