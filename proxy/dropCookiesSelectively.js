//@zaproxy-proxy

globalCookies = ['CONSENT', 'GZ', 'SID']

function proxyRequest(msg) {
    globalCookies.forEach(function (cookieToDrop) {
        cookies = msg.getRequestHeader().getHttpCookies() // This is a List<HttpCookie>
        iterator = cookies.iterator()
        while (iterator.hasNext()) {
            cookie = iterator.next() // This is a HttpCookie
            if (cookie.name == cookieToDrop) {
                iterator.remove()
                print('Stripped away: ' + cookie.name)
            }
        }
        msg.getRequestHeader().setCookies(cookies)
    })
    return true
}

function proxyResponse(msg) {
    return true
}
