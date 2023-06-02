# Version 1.0
# @author RUFFENACH Timothée
# filter by RTT (time request).

from javax.swing import JFrame, JPanel, JComboBox, JOptionPane,JFileChooser,JOptionPane

# Auxiliary variables/constants needed for processing.
global time,isCheck;
init = False

def getNumber(min,max,asked):
	number = JOptionPane.showInputDialog(None, asked, "Input", JOptionPane.QUESTION_MESSAGE)
    
	if int(number) >= min and int(number) <= max:
		number = int(number)
		return number
	else:
		JOptionPane.showMessageDialog(None, "Choose number between " +  min  + " to " + max)
		getNumber()

# Called after injecting the payloads and before forward the message to the server.
def processMessage(utils, message) :
	if (init == False):
		initialise()

def initialise():
	global init,entry,isCheck
	global time;
	time = getNumber(1,50000,"how many time do you want ?")
	isCheck = JOptionPane.showConfirmDialog(None, "more high or equal (YES) esle less or equal (NO)", "Confirm", JOptionPane.YES_NO_OPTION)
	init = True


# Called after receiving the fuzzed message from the server
def processResult(utils, fuzzResult) :
	global isChek,time
	if isCheck == JOptionPane.YES_OPTION and (int(fuzzResult.getHttpMessage().getTimeElapsedMillis()) >= time):
		return bool(1)
	elif isCheck == JOptionPane.NO_OPTION and (int(fuzzResult.getHttpMessage().getTimeElapsedMillis()) <= time):
		return bool(1)
	else:
		return bool(0);
	

