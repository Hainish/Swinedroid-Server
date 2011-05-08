#!/usr/bin/python
import cherrypy
from sys import path
path.append("./controllers")
from root import *

if __name__ == '__main__':
	cherrypy.quickstart(Root(), '/', CHERRYPY_CONFIG_FILE)
