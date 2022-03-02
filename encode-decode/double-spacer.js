var EncodeDecodeResult = Java.type("org.zaproxy.addon.encoder.processors.EncodeDecodeResult");

function process(value){
    // Replace any character (except last) with the character and a space
    return new EncodeDecodeResult(value.replaceAll(".(?=.)", "$0 ").trim());
}
