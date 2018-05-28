//@zaproxy-standalone

// This script will load export.js and a file from the Internet

print('loading scripts from: ' + java.lang.System.getProperty("user.dir"))

var number = 0 // This variable will be overwritten by the loading of export.js

// Load export.js
load("./export.js")

print(number)

print(customFunction('hello'))

// Load Loadash
load('https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js')

print(_.last([1, 2, 3]))
