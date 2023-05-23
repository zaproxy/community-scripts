# @author Timothée Ruffenach
# Version 1.0
# filters the fuzzing result with a string.

from javax.swing import JOptionPane


# global variable
init = False
entry = ""
isCheck = False

# Called after injecting the payloads and before forward the message to the server.
def processMessage(utils, message) :
    global number,payloads
    if not init:
        initialise()


def initialise():
    global init,entry,isCheck
    
    entry = ""

    # ask stings to find
    while entry == "":
        entry = getString("what character string do you want to find ?")
        if entry == "":
            JOptionPane.showMessageDialog(None, "Empty string","Waring", JOptionPane.WARNING_MESSAGE)
    # ask reverse message
    isCheck = JOptionPane.showConfirmDialog(None, "Reverse", "Confim", JOptionPane.YES_NO_OPTION)


    init = True

# Called after receiving the fuzzed message from the server
def processResult(utils, fuzzResult) :
    global entry,isCheck
    body = fuzzResult.getHttpMessage().getResponseBody().toString()

    # test all posibility
    if isCheck == JOptionPane.NO_OPTION and entry in body:
        return bool(1);
    elif isCheck == JOptionPane.YES_OPTION and not entry in body:
        return bool(1);
    else:
        return bool(0);

# Question
def getString(question):
        stringInput = JOptionPane.showInputDialog(None, question, "Input", JOptionPane.QUESTION_MESSAGE)
        return stringInput 
