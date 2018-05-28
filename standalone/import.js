//@zaproxy-standalone

// This script will load export.js

print('loading scripts from: ' + java.lang.System.getProperty("user.dir"))

var number = 0 // This variable will be overwritten by the loading of export.js

load("./export.js")

print(number)

print(customFunction('hello'))
