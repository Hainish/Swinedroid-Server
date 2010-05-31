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
	def index(self, username="", password="", call="", alert_severity="", search_term="", beginning_datetime="", ending_datetime="", starting_at="", limit="", sid="", cid=""):
		# Create a new xml document, append root
		xml = minidom.Document()
		root_elem = xml.createElement("root")
		xml.appendChild(root_elem)
		if username == swinedroid_username and password == swinedroid_password:
			try:
				if call=="overview":
					mysql_connection = MySQLdb.connect(host=mysql_host, user=mysql_username, passwd=mysql_password, db=mysql_database)
					mysql_cursor = mysql_connection.cursor()
					mysql_graph_cursor = mysql_connection.cursor()
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
					num_days = 10
					union_list = []
					for i in range(1, num_days + 1):
						union_list.append("SELECT 0, 0, date_format( SUBDATE(NOW(), INTERVAL " + str(i) + " day), '%m/%d'), 0")
					mysql_cursor.execute("""
						SELECT
							date,
							sig_priority,
							COUNT(sig_priority) AS sig_priority_count
						FROM (
							SELECT
								event.sid,
								event.cid,
								date_format( event.timestamp, '%m/%d' ) AS date,
								signature.sig_priority AS sig_priority
							FROM event
							LEFT JOIN signature ON
								event.signature=signature.sig_id
							WHERE date_format( SUBDATE(NOW(), INTERVAL """ + str(num_days) + """ day), '%Y-%m-%d') <= event.timestamp AND
								date_format(NOW(), '%Y-%m-%d') > event.timestamp
							UNION """ + " UNION ".join(union_list) + """
							) AS derived
						GROUP BY date, sig_priority
						ORDER BY
							date ASC,
							sig_priority ASC
						""")
					graph_statistics_elem = xml.createElement("graph_statistics")
					root_elem.appendChild(graph_statistics_elem)
					last_label = None
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						label, sig_priority, sig_priority_count = mysql_row
						if label != last_label:							
							graph_info_elem = xml.createElement("graph_info")
							graph_statistics_elem.appendChild(graph_info_elem)
							label_elem = xml.createElement("label")
							graph_info_elem.appendChild(label_elem)
							label_elem.appendChild(xml.createTextNode(label))
						if sig_priority == 1:
							sig_priority_elem = xml.createElement("low")
						if sig_priority == 2:
							sig_priority_elem = xml.createElement("medium")
						if sig_priority == 3:
							sig_priority_elem = xml.createElement("high")
						if sig_priority == 1 or sig_priority == 2 or sig_priority == 3:
							graph_info_elem.appendChild(sig_priority_elem)
							sig_priority_elem.appendChild(xml.createTextNode(str(sig_priority_count)))
						last_label = label
					mysql_connection.close()
				elif call == "alerts":
					mysql_connection = MySQLdb.connect(host=mysql_host, user=mysql_username, passwd=mysql_password, db=mysql_database)
					mysql_num_cursor = mysql_connection.cursor()
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
					mysql_num_cursor.execute("""
						SELECT
							COUNT(`event`.`sid`)
						FROM `event`
						LEFT JOIN `signature` ON
							`signature`.`sig_id`=`event`.`signature`
						WHERE %s
						""" % (' AND '.join(where_list)))
					num_alerts_elem = xml.createElement("num_alerts")
					root_elem.appendChild(num_alerts_elem)
					mysql_row = mysql_num_cursor.fetchone()
					if mysql_row != None:
						num_alerts, = mysql_row
					else:
						num_alerts = 0
					num_alerts_elem.appendChild(xml.createTextNode(str(num_alerts)))
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
						INNER JOIN `iphdr` ON
							`event`.`sid`=`iphdr`.`sid` AND
							`event`.`cid`=`iphdr`.`cid`
						WHERE %s
						ORDER BY `event`.`timestamp` DESC
						LIMIT %s, %s
						""" % (' AND '.join(where_list), starting_at_clean, limit_clean))
					alerts_elem = xml.createElement("alerts")
					root_elem.appendChild(alerts_elem)
					while 1:
						mysql_row = mysql_cursor.fetchone()
						if mysql_row == None:
							break
						sid, cid, ip_src, ip_dst, sig_priority, sig_name, timestamp = mysql_row
						alert_elem = xml.createElement("alert")
						alerts_elem.appendChild(alert_elem)
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
				elif call == "alert":
					mysql_connection = MySQLdb.connect(host=mysql_host, user=mysql_username, passwd=mysql_password, db=mysql_database)
					mysql_num_cursor = mysql_connection.cursor()
					mysql_cursor = mysql_connection.cursor()
					mysql_cursor.execute("""
						SELECT
							`tcphdr`.`tcp_sport`,
							`tcphdr`.`tcp_dport`,
							`udphdr`.`udp_sport`,
							`udphdr`.`udp_dport`,
							`icmphdr`.`icmp_type`,
							`icmphdr`.`icmp_code`,
							`sensor`.`hostname`,
							`sensor`.`interface`,
							`data`.`data_payload`
						FROM (SELECT '%s' AS sid, '%s' AS cid) AS `abstract`
						LEFT JOIN `tcphdr` ON
							`abstract`.`sid`=`tcphdr`.`sid` AND
							`abstract`.`cid`=`tcphdr`.`cid`
						LEFT JOIN `udphdr` ON
							`abstract`.`sid`=`udphdr`.`sid` AND
							`abstract`.`cid`=`udphdr`.`cid`
						LEFT JOIN `icmphdr` ON
							`abstract`.`sid`=`icmphdr`.`sid` AND
							`abstract`.`cid`=`icmphdr`.`cid`
						LEFT JOIN `data` ON
							`abstract`.`sid`=`data`.`sid` AND
							`abstract`.`cid`=`data`.`cid`
						LEFT JOIN `sensor` ON
							`abstract`.`sid`=`sensor`.`sid`
						""" % (sid, cid))
					mysql_row = mysql_cursor.fetchone()
					if mysql_row != None:
						print mysql_row
						tcp_sport, tcp_dport, udp_sport, udp_dport, icmp_type, icmp_code, hostname, interface, data_payload = mysql_row
						alert_elem = xml.createElement("alert")
						root_elem.appendChild(alert_elem)
						protocol_elem = xml.createElement("protocol")
						alert_elem.appendChild(protocol_elem)
						if tcp_sport != None:
							protocol_elem.appendChild(xml.createTextNode("tcp"))
							sport_elem = xml.createElement("sport")
							alert_elem.appendChild(sport_elem)
							sport_elem.appendChild(xml.createTextNode(str(tcp_sport)))
							dport_elem = xml.createElement("dport")
							alert_elem.appendChild(dport_elem)
							dport_elem.appendChild(xml.createTextNode(str(tcp_dport)))
						elif udp_sport != None:
							protocol_elem.appendChild(xml.createTextNode("udp"))
							sport_elem = xml.createElement("sport")
							alert_elem.appendChild(sport_elem)
							sport_elem.appendChild(xml.createTextNode(str(udp_sport)))
							dport_elem = xml.createElement("dport")
							alert_elem.appendChild(dport_elem)
							dport_elem.appendChild(xml.createTextNode(str(udp_dport)))
						elif icmp_type != None:
							protocol_elem.appendChild(xml.createTextNode("icmp"))
							type_elem = xml.createElement("type")
							alert_elem.appendChild(type_elem)
							type_elem.appendChild(xml.createTextNode(str(icmp_type)))
							code_elem = xml.createElement("code")
							alert_elem.appendChild(code_elem)
							code_elem.appendChild(xml.createTextNode(str(icmp_code)))
						else:
							protocol_elem.appendChild(xml.createTextNode("undefined"))
						hostname_elem = xml.createElement("hostname")
						alert_elem.appendChild(hostname_elem)
						hostname_elem.appendChild(xml.createTextNode(str(hostname)))
						interface_elem = xml.createElement("interface")
						alert_elem.appendChild(interface_elem)
						interface_elem.appendChild(xml.createTextNode(str(interface)))
						payload_elem = xml.createElement("payload")
						alert_elem.appendChild(payload_elem)
						payload_elem.appendChild(xml.createTextNode(str(data_payload)))
					else:
						error_elem = xml.createElement("error")
						error_elem.appendChild(xml.createTextNode("Invalid alert."))
						root_elem.appendChild(error_elem)
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

