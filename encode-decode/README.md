Encode/Decode/Hash scripts
==================

Scripts that are meant to process input and output it in a different form, for use in the Encode/Decode/Hash tool.
https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/ 

## JavaScript template

```js

/**
 * Process the input value and return the encoded/decoded/hashed etc. value
 *
 * Use helper.newError("Error Description") to provide an error description
 * inside the result view.
 *
 * @param {EncodeDecodeScriptHelper} helper - A helper object with various utility methods.
 *     For more details see https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java
 * @param {String} value - The input value
 * @returns {EncodeDecodeResult} - The value that was encoded/decoded/hashed etc. easiest via helper.newResult(result).
 */
function process(helper, value){
	return helper.newResult("TEST");
}
```

## Parameters

| Name | JavaDoc/Reference |
| ---- | ------- |
| helper | [EncodeDecodeScriptHelper](https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java)
| value | [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html) |
