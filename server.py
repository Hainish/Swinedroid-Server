#!/usr/bin/python
import cherrypy, ConfigParser, MySQLdb, re
from xml.dom import minidom

CHERRYPY_CONFIG_FILE = 		"cherrypy.conf"
SWINEDROID_CONFIG_FILE = 	"swinedroid.conf"

config = ConfigParser.ConfigParser()
config.read(SWINEDROID_CONFIG_FILE)

# load swinedroid config
if config.has_option('swinedroid','username'):
	swinedroid_username = config.get('swinedroid','username')
if config.has_option('swinedroid','password'):
	swinedroid_password = config.get('swinedroid','password')

# load mysql config
if config.has_option('mysql','host'):
	mysql_host = config.get('mysql','host')
if config.has_option('mysql','username'):
	mysql_username = config.get('mysql','username')
if config.has_option('mysql','password'):
	mysql_password = config.get('mysql','password')
if config.has_option('mysql','database'):
	mysql_database = config.get('mysql','database')

class Root:
	def index(self, username="", password="", call="", alert_severity="", search_term="", beginning_datetime="", ending_datetime="", starting_at="", limit=""):
		# Create a new xml document, append root
		xml = minidom.Document()
		root_elem = xml.createElement("root")
		xml.appendChild(root_elem)
		if username == swinedroid_username and password == swinedroid_password:
			try:
				if call=="overview":
					mysql_connection = MySQLdb.connect(host=mysql_host, user=mysql_username, passwd=mysql_password, db=mysql_database)
					mysql_cursor = mysql_connection.cursor()
					severity_all_time = {1: 0, 2: 0, 3: 0}
					severity_last_72 = {1: 0, 2: 0, 3: 0}
					severity_last_24 = {1: 0, 2: 0, 3: 0}
					severity_profile_elem = xml.createElement("severity_profile")
					root_elem.appendChild(severity_profile_elem)
					mysql_cursor.execute("""
						SELECT
							`signature`.`sig_priority`,
							COUNT(`signature`.`sig_priority`)
						FROM `event`
						LEFT JOIN `signature` ON
							`signature`.`sig_id`=`event`.`signature`
						WHERE 1
						GROUP BY
							`signature`.`sig_priority`
						""")
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						severity_index, alert = mysql_row
						severity_all_time[int(severity_index)] = int(alert)
					all_time_elem = xml.createElement("all_time")
					severity_profile_elem.appendChild(all_time_elem)
					all_time_high_severity_elem = xml.createElement("high")
					all_time_elem.appendChild(all_time_high_severity_elem)
					all_time_high_severity_elem.appendChild(xml.createTextNode(str(severity_all_time[3])))
					all_time_medium_severity_elem = xml.createElement("medium")
					all_time_elem.appendChild(all_time_medium_severity_elem)
					all_time_medium_severity_elem.appendChild(xml.createTextNode(str(severity_all_time[2])))
					all_time_low_severity_elem = xml.createElement("low")
					all_time_elem.appendChild(all_time_low_severity_elem)
					all_time_low_severity_elem.appendChild(xml.createTextNode(str(severity_all_time[1])))
					mysql_cursor.execute("""
						SELECT
							`signature`.`sig_priority`,
							COUNT(`signature`.`sig_priority`)
						FROM `event`
						LEFT JOIN `signature` ON
							`signature`.`sig_id`=`event`.`signature`
						WHERE SUBDATE(NOW(), INTERVAL 72 HOUR) <= `event`.`timestamp`
						GROUP BY
							`signature`.`sig_priority`
						""")
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						severity_index, alert = mysql_row
						severity_last_72[int(severity_index)] = int(alert)
					last_72_elem = xml.createElement("last_72")
					severity_profile_elem.appendChild(last_72_elem)
					last_72_high_severity_elem = xml.createElement("high")
					last_72_elem.appendChild(last_72_high_severity_elem)
					last_72_high_severity_elem.appendChild(xml.createTextNode(str(severity_last_72[3])))
					last_72_medium_severity_elem = xml.createElement("medium")
					last_72_elem.appendChild(last_72_medium_severity_elem)
					last_72_medium_severity_elem.appendChild(xml.createTextNode(str(severity_last_72[2])))
					last_72_low_severity_elem = xml.createElement("low")
					last_72_elem.appendChild(last_72_low_severity_elem)
					last_72_low_severity_elem.appendChild(xml.createTextNode(str(severity_last_72[1])))
					mysql_cursor.execute("""
						SELECT
							`signature`.`sig_priority`,
							COUNT(`signature`.`sig_priority`)
						FROM `event`
						LEFT JOIN `signature` ON
							`signature`.`sig_id`=`event`.`signature`
						WHERE SUBDATE(NOW(), INTERVAL 24 HOUR) <= `event`.`timestamp`
						GROUP BY
							`signature`.`sig_priority`
						""")
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						severity_index, alert = mysql_row
						severity_last_24[int(severity_index)] = int(alert)
					last_24_elem = xml.createElement("last_24")
					severity_profile_elem.appendChild(last_24_elem)
					last_24_high_severity_elem = xml.createElement("high")
					last_24_elem.appendChild(last_24_high_severity_elem)
					last_24_high_severity_elem.appendChild(xml.createTextNode(str(severity_last_24[3])))
					last_24_medium_severity_elem = xml.createElement("medium")
					last_24_elem.appendChild(last_24_medium_severity_elem)
					last_24_medium_severity_elem.appendChild(xml.createTextNode(str(severity_last_24[2])))
					last_24_low_severity_elem = xml.createElement("low")
					last_24_elem.appendChild(last_24_low_severity_elem)
					last_24_low_severity_elem.appendChild(xml.createTextNode(str(severity_last_24[1])))
					mysql_connection.close()
				elif call == "alerts":
					mysql_connection = MySQLdb.connect(host=mysql_host, user=mysql_username, passwd=mysql_password, db=mysql_database)
					mysql_cursor = mysql_connection.cursor()
					where_list = []
					if alert_severity == "High":
						where_list.append("signature.sig_priority='3'")
					if alert_severity == "Medium":
						where_list.append("signature.sig_priority='2'")
					if alert_severity == "Low":
						where_list.append("signature.sig_priority='1'")
					if search_term != "":
						where_list.append("signature.sig_name LIKE '%" + search_term + "%'")
					if beginning_datetime != "":
						where_list.append("event.timestamp > '" + beginning_datetime + "'")
					if ending_datetime != "":
						where_list.append("event.timestamp < '" + ending_datetime + "'")
					if len(where_list) == 0:
						where_list.append("1")
					if re.match(r'^[0-9]+$', starting_at) != None:
						starting_at_clean = starting_at
					else:
						starting_at_clean = "0"
					if re.match(r'^[0-9]+$', limit) != None:
						limit_clean = limit
					else:
						limit_clean = "30"
					mysql_cursor.execute("""
						SELECT
							`event`.`sid`,
							`event`.`cid`,
							`iphdr`.`ip_src`,
							`iphdr`.`ip_dst`,
							`signature`.`sig_priority`,
							`signature`.`sig_name`,
							`event`.`timestamp`
						FROM `event`
						LEFT JOIN `signature` ON
							`signature`.`sig_id`=`event`.`signature`
						LEFT JOIN `iphdr` ON
							`event`.`sid`=`iphdr`.`sid` AND
							`event`.`cid`=`iphdr`.`cid`
						WHERE %s
						ORDER BY `event`.`timestamp` DESC
						LIMIT %s, %s
						""" % (' AND '.join(where_list), starting_at_clean, limit_clean))
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						sid, cid, ip_src, ip_dst, sig_priority, sig_name, timestamp = mysql_row
						alert_elem = xml.createElement("alert")
						root_elem.appendChild(alert_elem)
						sid_elem = xml.createElement("sid")
						sid_elem.appendChild(xml.createTextNode(str(sid)))
						alert_elem.appendChild(sid_elem)
						cid_elem = xml.createElement("cid")
						cid_elem.appendChild(xml.createTextNode(str(cid)))
						alert_elem.appendChild(cid_elem)
						ip_src_elem = xml.createElement("ip_src")
						ip_src_elem.appendChild(xml.createTextNode(str(ip_src)))
						alert_elem.appendChild(ip_src_elem)
						ip_dst_elem = xml.createElement("ip_dst")
						ip_dst_elem.appendChild(xml.createTextNode(str(ip_dst)))
						alert_elem.appendChild(ip_dst_elem)
						sig_priority_elem = xml.createElement("sig_priority")
						sig_priority_elem.appendChild(xml.createTextNode(str(sig_priority)))
						alert_elem.appendChild(sig_priority_elem)
						sig_name_elem = xml.createElement("sig_name")
						sig_name_elem.appendChild(xml.createTextNode(str(sig_name)))
						alert_elem.appendChild(sig_name_elem)
						timestamp_elem = xml.createElement("timestamp")
						timestamp_elem.appendChild(xml.createTextNode(str(timestamp)))
						alert_elem.appendChild(timestamp_elem)
					mysql_connection.close()
				else:
					error_elem = xml.createElement("error")
					error_elem.appendChild(xml.createTextNode("Invalid call."))
					root_elem.appendChild(error_elem)
			except MySQLdb.Error, e:
				print "Error: %d: %s" % (e.args[0], e.args[1])
				error_elem = xml.createElement("error")
				error_elem.appendChild(xml.createTextNode("A MySQL error has occurred.  Please check your MySQL server settings and try again later."))
				root_elem.appendChild(error_elem)
		else:
			error_elem = xml.createElement("error")
			error_elem.appendChild(xml.createTextNode("Incorrect username or password."))
			root_elem.appendChild(error_elem)
		cherrypy.response.headers['Content-Type'] = "text/xml"
		return xml.toxml("UTF-8")
	index.exposed = True

cherrypy.quickstart(Root(), '/', CHERRYPY_CONFIG_FILE)

