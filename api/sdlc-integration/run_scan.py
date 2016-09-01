# This script should be used to run the actual ZAP scan

import sys
import core.scan_module.scan as scan

scan.main(sys.argv[1:])
