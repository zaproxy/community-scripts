# @author RUFFENACH Timothée
# Version 1.1
# Scrip to edit file
# Help me for lab burpsuite resolve with zap

from javax.swing import JFrame, JPanel, JComboBox, JOptionPane,JFileChooser,JOptionPane
from java.io import File, FileWriter
from java.awt.event import WindowAdapter, WindowEvent
from java.awt import Toolkit

class SelectionMenu(JFrame):
    def __init__(self):
        JFrame.__init__(self, "Selection Menu")
        self.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)
        self.setSize(500, 300)
        self.getContentPane().setLayout(None)

        # Create selection menu
        options = ["Inserting a character string alternately", "Duplicate data file", "Create Json tab with data file"]

        # Create scrolling menu
        self.dropdown = JComboBox(options)
        self.dropdown.setBounds(50, 50, 400, 20)
        self.dropdown.addActionListener(self.selection_changee)
        self.getContentPane().add(self.dropdown)

        # center windows
        self.center_window()

        # Add event listener for closing the window
        self.addWindowListener(CustomWindowAdapter())

    def selection_changee(self, event):
        selected_option = self.dropdown.getSelectedItem()
        
        if selected_option == "Inserting a character string alternately":
            self.dropdown.setPopupVisible(False)
            self.fonction_option1()
        elif selected_option == "Duplicate data file":
            self.dropdown.setPopupVisible(False)
            self.fonction_option2()
        elif selected_option == "Create Json tab with data file":
            self.dropdown.setPopupVisible(False)
            self.fonction_option3()

        # close scrolling menu
        self.dropdown.setPopupVisible(False)

    def fonction_option1(self):
        
        # get mandatory data
        alternate = self.getNumber(1,100, "How many alternate do you want between [1 to 100]")
        print("alternate number", alternate)
        string = self.getString()
        print("string", string)
        filePath = self.chooseFile()
        print("path", filePath)

 
        # get number line of file
        file = open(filePath, "r")
        nb_line = 0
        for line in file:
            nb_line += 1
        file.close()

        # the file can't have 0 line
        if nb_line == 0:
            JOptionPane.showMessageDialog(None, "Empty file", "Alerte", JOptionPane.WARNING_MESSAGE)
            return 0
        
        # alternate must slower line of file
        if alternate > nb_line:
            JOptionPane.showMessageDialog(None, "The alternate line don't not more greatet when the line of file", "Alerte", JOptionPane.WARNING_MESSAGE)
            return 0
        
        # read data of file
        file = open(filePath, "r")
        data = file.readlines()
        file.close()

        # add \n to data
        string += "\n"

        # make new data
        i = alternate  
        while i < len(data):
            data.insert(i,string)
            i += alternate + 1

        self.saveFile(data)

    def fonction_option2(self):
       
        copy = self.getNumber(1,100, "How many copy data file do you want [1 to 100]")
        filePath = self.chooseFile()
        print("path", filePath)

        self.getNumberLine(filePath)
        
        # read data of file
        file = open(filePath, "r")
        data = file.readlines()
        file.close()
       
        dataCopy=[]
        for i in range(copy):
            dataCopy = dataCopy + data

        self.saveFile(dataCopy)
    
    def fonction_option3(self):
       
        filePath = self.chooseFile()
        print("path", filePath)
        
        # read data of file
        file = open(filePath, "r")
        data = file.readlines()
        file.close()
       
        # get numberline
        self.getNumberLine(filePath) 
        
        # create tab JSon
        dataJson =[]
        dataJson.append("[\n")

        for i in range(len(data)):
            if(i < len(data)-1):
                dataJson.append("\""+data[i].rstrip('\n')+"\",\n")
            else:
                dataJson.append("\""+data[i].rstrip('\n')+"\"\n")
        
        dataJson.append("]\n")

        self.saveFile(dataJson)
        
    # get number line file
    def getNumberLine(self,filePath):
        nb_line = 0        

        while nb_line < 1:
            file = open(filePath, "r")

            for line in file:
                nb_line += 1
            file.close()

            # the file can't have 0 line
            if nb_line == 0:
                JOptionPane.showMessageDialog(None, "Empty file", "Alerte", JOptionPane.WARNING_MESSAGE)

        return nb_line
    
    def saveFile(self,data):
        # create instance JFileChooser
        file_chooser = JFileChooser()

        # show dialog box 
        result = file_chooser.showSaveDialog(None)

        if result == JFileChooser.APPROVE_OPTION:
            # get select file
            file = file_chooser.getSelectedFile()

            # get path
            path_file = file.getAbsolutePath()

            # write data
            with open(path_file, "w") as file:
                for i in range(len(data)):
                    file.write(data[i])

            print("File saved :", path_file)
        else:
            print("Save cancel.")

    def chooseFile(self):
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


    def getNumber(self,min,max,asked):
        number = JOptionPane.showInputDialog(None, asked, "Input", JOptionPane.QUESTION_MESSAGE)
    
        if int(number) >= min and int(number) <= max:
            number = int(number)
            return number
        else:
            JOptionPane.showMessageDialog(None, "Choose number between " +  min  + " to " + max)
            self.chooseNumber()


    def getString(self):
        stringInput = JOptionPane.showInputDialog(None, "what is your string : ", "Input", JOptionPane.QUESTION_MESSAGE)
    
        return stringInput 
      
    
    def center_window(self):
        screenSize = Toolkit.getDefaultToolkit().getScreenSize()
        screenWidth = screenSize.width
        screenHeight = screenSize.height
        windowWidth = self.getWidth()
        windowHeight = self.getHeight()

        # caclul to center windows
        posX = (screenWidth - windowWidth) // 2
        posY = (screenHeight - windowHeight) // 2

        self.setLocation(posX, posY)

class CustomWindowAdapter(WindowAdapter):
    def windowClosing(self, event):
        confirm_closing()

def confirm_closing():
    reponse = JOptionPane.showConfirmDialog(None, "Do you want close script ?", "Confirmation", JOptionPane.YES_NO_OPTION)
    if reponse == JOptionPane.YES_OPTION:
        menu.dispose()  # close windows en free up resouces
    else:
        pass  # do nothing

# menu
menu = SelectionMenu()
menu.setVisible(True)
