// Auxiliary variables/constants for payload generation.
var SecureRandom = Java.type("java.security.SecureRandom");
var random = new SecureRandom();
var NUMBER_OF_PAYLOADS = 10;
var INITIAL_VALUE = 1;
var count = INITIAL_VALUE;

function getNumberOfPayloads() {
	return NUMBER_OF_PAYLOADS;
}

function hasNext() {
	return (count <= NUMBER_OF_PAYLOADS);
}

function next() {
	count++;
	// There are other data type options offered by SecureRandom
	// https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/SecureRandom.html
	// If you don't want leading negative signs on ints you could use Math.abs
	// If you want to pad to a certain length you could do something like:
	// String.format("%010d", random.nextint());'
	return random.nextInt();
}

function reset() {
	count = INITIAL_VALUE;
}

function close() {
}
