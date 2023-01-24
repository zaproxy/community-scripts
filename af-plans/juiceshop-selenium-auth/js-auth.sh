# Ensure that ZAP is set to the full path of the zap.sh script installed

# Standard macOS location
# ZAP=/Applications/OWASP\ ZAP.app/Contents/Java/zap.sh

ZAP=zap.sh

export JS_USER=test@test.com
export JS_PWD=test123

$ZAP -cmd -autorun /full/path/juiceshop-auth.yaml 

