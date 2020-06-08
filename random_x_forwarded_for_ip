function processMessage(utils, message) {
	random_ip = Math.floor(Math.random() * 254)+ "." + Math.floor(Math.random() * 254) + "." + Math.floor(Math.random() * 254) + "." + Math.floor(Math.random() * 254);
	message.getRequestHeader().setHeader("X-Forwarded-For", random_ip);
}

function processResult(utils, fuzzResult){
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}
