# Version 1.1
# @author RUFFENACH Timothée
# Script inspired from https://02108124551050482571.googlegroups.com/attach/54c6e34f6fe20/message_processor.js?part=0.1&view=1&vt=ANaJVrEJuACewYorhYYa_zyhyMSug06pmlERCqfYdLsukQBC3OW3LATuXG1WHk_Fw9a0nhexG8ykFDuFgBGYrKAg_pOQ61M36MwC9SOBGvK4KLZn3eDkNzY (dot run on owasp 2.12.0)
# To resolve problem at from https://github.com/zaproxy/zaproxy/issues/2967
# The script fuzz in mode pitchfork.
# To Use : Enable script.
# In fuzzer Add number multiple EmptyNull payloads with a good number of iterations.
# Select the desired number of payloads [limit 2 to 20]
# Select the desired number of files    [limit 2 to 20]

from java.nio.file import Paths
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from org.zaproxy.zap.extension.fuzz.payloads.generator import FileStringPayloadGenerator

payloads1 = None
payloads2 = None
init = False

def processMessage(utils, message):
    global number, payloads, init
    
    if not init:
        initialise()
    
    # Stop if has end of payloads
    for i in range(number):
        # if end of payload stop fuzzing
        if not payloads[i].hasNext():
            utils.stopFuzzer()
            # close all payload
            for j in range(number):
                payloads.close()
            return
    
    for i in range(number):
        # Get the next value of payloads
        # Get information of body and replace with payload value
        payloadNext = payloads[i].next().getValue()
        body = message.getRequestBody().toString()
        body = body.replace(utils.getPaylaods().get(i).getValue(), payloadNext)
        # Set payload value to show in Fuzzer 
        utils.getPaylaods().set(i,payloadNext)
        # set payload in body
        message.getRequestBody().setBody(body)
        message.getRequestHeader().setContentLength(message.getRequestBody().length())

def processResult(utils, fuzzResult):
    return True

def chooseFile():
    fileChooser = JFileChooser()
    fileChooser.setMultiSelectionEnabled(True)
    filePath = ""
    result = fileChooser.showOpenDialog(None)

    if result == JFileChooser.APPROVE_OPTION:
        selectedFiles = fileChooser.getSelectedFiles()
        for file in selectedFiles:
            filePath = file.getAbsolutePath()
            print('The path is :', filePath)

    return filePath

def chooseNumber():
    number = JOptionPane.showInputDialog(None, "How many payload do you want [2 to 20]:", "Input", JOptionPane.QUESTION_MESSAGE)
    
    # Check number between 2 to 20
    if int(number) > 1 and int(number) < 21:
        number = int(number)
        return number
    else:
        JOptionPane.showMessageDialog(None, "Choose number between 2 to 20")
        chooseNumber()

def initialise():
    global init
    global payloads
    global number
    
    payloads = []
    filePaths = []

    # input number of payloads
    number = -1
    while number == -1:
        number = chooseNumber()

    # add files chosen by the user        
    for i in range(number):
        filePaths.append(chooseFile())

    # Get payload in file to var payloads    
    for i in range(number):
        payloads.append(FileStringPayloadGenerator(Paths.get(filePaths[i])).iterator())
    
    init = True
