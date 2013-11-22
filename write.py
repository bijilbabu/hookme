import sys
f = open('/home/helios/SECRET.TXT', 'w')
f.write(sys.argv[1])
f.close()