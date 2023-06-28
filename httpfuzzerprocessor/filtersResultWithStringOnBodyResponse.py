# @author Timothée Ruffenach
# Version 1.1
# filters the fuzzing result with a string.

from javax.swing import JOptionPane


# global variable
init = False
entry = ""
choice = False

# Called after injecting the payloads and before forward the message to the server.
def processMessage(utils, message) :
    global number,payloads
    if not init:
        initialise()


def initialise():
    global init,entry,choice
    
    entry = ""

    # ask stings to find
    while entry == "":
        entry = getString("What character string do you want to find ?")
        if entry == "":
            JOptionPane.showMessageDialog(None, "Empty string","Warning", JOptionPane.WARNING_MESSAGE)
    # ask reverse message
    choice = JOptionPane.showConfirmDialog(None, "Do you want to reverse the search result ?", "Confim", JOptionPane.YES_NO_OPTION)

    init = True

# Called after receiving the fuzzed message from the server
def processResult(utils, fuzzResult) :
    global entry,choice
    body = fuzzResult.getHttpMessage().getResponseBody().toString()

    # test all posibility
    if choice == JOptionPane.NO_OPTION and entry in body:
        return True;
    elif choice == JOptionPane.YES_OPTION and not entry in body:
        return True;
    else:
        return False;

# Question
def getString(question):
        stringInput = JOptionPane.showInputDialog(None, question, "Input", JOptionPane.QUESTION_MESSAGE)
        return stringInput 
