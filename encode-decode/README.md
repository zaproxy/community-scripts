Encode/Decode/Hash scripts
==================

Scripts that are meant to process input and output it in a different form, for use in the Encode/Decode/Hash tool.
https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/ 

## JavaScript template

```js
var EncodeDecodeResult = Java.type("org.zaproxy.addon.encoder.processors.EncodeDecodeResult");

/**
 * Process the input value and return the encoded/decoded/hashed etc. value
 *
 * Use EncodeDecodeResult.withError("Error Description") to provide an error description
 * inside the result view
 *
 * @param {String} value - The input value
 * @returns {EncodeDecodeResult} - The value that was encoded/decoded/hashed etc.
 */
function process(value){
	return new EncodeDecodeResult("TEST");
}
```

## Parameters

| Name | JavaDoc |
| ---- | ------- |
| value | [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html) |
