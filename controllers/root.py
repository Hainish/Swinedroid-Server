class Root:
	def index(self, username="", password="", call="", alert_severity="", search_term="", beginning_datetime="", ending_datetime="", starting_at="", limit="", sid="", cid=""):
		# Create a new xml document, append root
		xml = minidom.Document()
		root_elem = xml.createElement("root")
		xml.appendChild(root_elem)
		if username == swinedroid_username and password == swinedroid_password:
			try:
				if call=="overview":
					session = sqlalchemy_handle()
					# Prepare severity profiles
					severity_all_time = {1: 0, 2: 0, 3: 0}
					severity_last_72 = {1: 0, 2: 0, 3: 0}
					severity_last_24 = {1: 0, 2: 0, 3: 0}
					severity_profile_elem = xml.createElement("severity_profile")
					root_elem.appendChild(severity_profile_elem)
					# Start all-time statistics gathering
					all_time_results = session.query(
							func.count(Event.sid),
							Signature.sig_priority).\
						join(Signature).\
						group_by(Signature.sig_priority).all()
					for all_time_event_count, all_time_priority in all_time_results:
						severity_all_time[all_time_priority] = all_time_event_count
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
					# Start 72-hour statistics gathering
					last_72_results = session.query(
							func.count(Event.sid),
							Signature.sig_priority).\
						join(Signature).\
						filter(Event.timestamp >= dbc.subdays(3)).\
						group_by(Signature.sig_priority).all()
					for last_72_event_count, last_72_priority in last_72_results:
						severity_last_72[last_72_priority] = last_72_event_count
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
					# Start 24-hour statistics gathering
					last_24_results = session.query(
							func.count(Event.sid),
							Signature.sig_priority).\
						join(Signature).\
						filter(Event.timestamp >= dbc.subdays(1)).\
						group_by(Signature.sig_priority).all()
					for last_24_event_count, last_24_priority in last_24_results:
						severity_last_24[last_24_priority] = last_24_event_count
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
					# Start preparation for graph
					graph_statistics_elem = xml.createElement("graph_statistics")
					root_elem.appendChild(graph_statistics_elem)
					last_label = None
					num_days = 10
					union_alerts = []
					for i in range(1, num_days + 1):
						union_alerts.append(
							session.query(
									literal('0'),
									literal(0),
									dbc.date_output(dbc.subdays(i)),
									literal('0')))
					all_alerts = session.query(
							Event.sid, literal(1).label('for_sum'),
							dbc.date_output(Event.timestamp).label('date'),
							Signature.sig_priority.label('sig_priority')).\
						join(Signature).\
						filter(
							and_(
								dbc.date_compare(dbc.subdays(10)) <= Event.timestamp,
								dbc.date_compare(func.now()) > Event.timestamp)).\
						union_all(*union_alerts).subquery()
					grouped_alerts = session.query(
							all_alerts.columns.date,
							all_alerts.columns.sig_priority,
							func.sum(all_alerts.columns.for_sum)).\
						group_by(all_alerts.columns.date, all_alerts.columns.sig_priority).\
						order_by(all_alerts.columns.date, all_alerts.columns.sig_priority).all()
					for label, sig_priority, sig_sum in grouped_alerts:
						sig_priority = int(sig_priority)
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
							sig_priority_elem.appendChild(xml.createTextNode(str(sig_sum)))
						last_label = label
					session.close()
				elif call == "alerts":
					session = sqlalchemy_handle()
					# Get conditions from any search parameters passed to us
					condition_list = []
					if alert_severity == "High":
						condition_list.append(Signature.sig_priority == 3)
					if alert_severity == "Medium":
						condition_list.append(Signature.sig_priority == 2)
					if alert_severity == "Low":
						condition_list.append(Signature.sig_priority == 1)
					if search_term != "":
						condition_list.append(Signature.sig_name.like("%" + search_term + "%"))
					if beginning_datetime != "":
						condition_list.append(Event.timestamp > dbc.date_time_to_timestamp(beginning_datetime))
					if ending_datetime != "":
						condition_list.append(Event.timestamp < dbc.date_time_to_timestamp(ending_datetime))
					# Sanitize our limit and offset
					if re.match(r'^[0-9]+$', starting_at) != None:
						starting_at_clean = starting_at
					else:
						starting_at_clean = "0"
					if re.match(r'^[0-9]+$', limit) != None:
						limit_clean = int(limit)
					else:
						limit_clean = 30
					# Determine total number of alerts
					num_alerts, = session.query(func.count(Event.sid)).\
						join(Signature, (IpHdr, Event.iphdr)).\
						filter(and_(*condition_list)).one()
					num_alerts_elem = xml.createElement("num_alerts")
					root_elem.appendChild(num_alerts_elem)
					num_alerts_elem.appendChild(xml.createTextNode(str(num_alerts)))
					# Get alerts, passing the conditional, and output
					alerts = session.query(
							Event.sid,
							Event.cid,
							IpHdr.ip_src,
							IpHdr.ip_dst,
							Signature.sig_priority,
							Signature.sig_name,
							Event.timestamp).\
						join(Signature, (IpHdr, Event.iphdr)).\
						filter(and_(*condition_list)).order_by(desc(Event.timestamp)).\
						limit(limit_clean).offset(starting_at_clean).all()
					alerts_elem = xml.createElement("alerts")
					root_elem.appendChild(alerts_elem)
					for sid, cid, ip_src, ip_dst, sig_priority, sig_name, timestamp in alerts:
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
					session.close()
				elif call == "alert":
					session = sqlalchemy_handle()
					try:
						# Query alert in a series of join statements
						tcp_sport, tcp_dport, udp_sport, udp_dport, icmp_type, icmp_code, hostname, interface, data_payload = session.query(
								TcpHdr.tcp_sport,
								TcpHdr.tcp_dport,
								UdpHdr.udp_sport,
								UdpHdr.udp_dport,
								IcmpHdr.icmp_type,
								IcmpHdr.icmp_code,
								Sensor.hostname,
								Sensor.interface,
								Data.data_payload
							).\
							select_from(Event).\
							outerjoin(
								(TcpHdr, Event.tcphdr),
								(UdpHdr, Event.udphdr),
								(IcmpHdr, Event.icmphdr),
								(Sensor, Event.sensor),
								(Data, Event.data)
							).filter(and_(Event.sid == sid, Event.cid == cid)).one()
						alert_elem = xml.createElement("alert")
						root_elem.appendChild(alert_elem)
						protocol_elem = xml.createElement("protocol")
						alert_elem.appendChild(protocol_elem)
						# Display relevant information based on what fields are returned
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
						if data_payload != None:
							payload_elem = xml.createElement("payload")
							alert_elem.appendChild(payload_elem)
							payload_elem.appendChild(xml.createTextNode(str(data_payload)))
					except (NoResultFound, MultipleResultsFound):
						# No / multiple results found? output error
						error_elem = xml.createElement("error")
						error_elem.appendChild(xml.createTextNode("Invalid alert."))
						root_elem.appendChild(error_elem)
					session.close()
				elif call == "ipfilter":
					print "test"
				else:
					error_elem = xml.createElement("error")
					error_elem.appendChild(xml.createTextNode("Invalid call."))
					root_elem.appendChild(error_elem)
			except OperationalError, e:
				# In case of invalid password or db server not running
				print e.args[0]
				error_elem = xml.createElement("error")
				error_elem.appendChild(xml.createTextNode("A database error has occurred.  Please check your database server settings and try again later."))
				root_elem.appendChild(error_elem)
		else:
			error_elem = xml.createElement("error")
			error_elem.appendChild(xml.createTextNode("Swinedroid: Incorrect username or password."))
			root_elem.appendChild(error_elem)
		cherrypy.response.headers['Content-Type'] = "text/xml"
		return xml.toxml("UTF-8")
	index.exposed = True


