import ConfigParser, re
from xml.dom import minidom
from schema import *
import cherrypy

CHERRYPY_CONFIG_FILE = 		"cherrypy.conf"
SWINEDROID_CONFIG_FILE = 	"swinedroid.conf"

config = ConfigParser.ConfigParser()
config.read(SWINEDROID_CONFIG_FILE)

# load swinedroid config
if config.has_option('swinedroid','username'):
	swinedroid_username = config.get('swinedroid','username')
if config.has_option('swinedroid','password'):
	swinedroid_password = config.get('swinedroid','password')

# load database config
if config.has_option('database','database'):
	database_database = config.get('database','database')
if config.has_option('database','host'):
	database_host = config.get('database','host')
if config.has_option('database','username'):
	database_username = config.get('database','username')
if config.has_option('database','password'):
	database_password = config.get('database','password')
if config.has_option('database','name'):
	database_name = config.get('database','name')
if config.has_option('database','writable'):
	database_writable = config.get('database','writable')

dbc = DbConversion(database_database)

def sqlalchemy_handle():
	engine = create_engine(database_database + '://' + database_username + ':' + database_password + '@' + database_host + '/' + database_name, echo=False)
	Session = sessionmaker(bind=engine)
	return Session()
