# Version 1.1
# @author RUFFENACH Timothée
# filter by RTT (time request).

from javax.swing import JFrame, JPanel, JComboBox, JOptionPane,JFileChooser,JOptionPane

# Auxiliary variables/constants needed for processing.
global time,choice,init;
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
def processMessage(utils, message):
	global init;
	if (init == False):
		shouldInit()

# Initialisation 
def shouldInit():
	global time, choice,init;
	options = ["MORE", "LESS"] # choice options

	time = getNumber(1,50000,"What is the value of RTT (Raquest and Response Timing) do you want ?")
	
	choice = JOptionPane.showOptionDialog(
		None, "Do want the value to be greater or equal than  to the previous input (MORE) or smaller or equal (LESS)", 
		"Confirm", 
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE,
		None,
		options,
		options[0]
		)
	init = True