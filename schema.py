#!/usr/bin/env python

from sqlalchemy import create_engine, Column, Integer, SmallInteger, DateTime, String, Text, and_, ForeignKey, desc, func, literal
from sqlalchemy.orm import sessionmaker, relation, backref
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import text

Base = declarative_base()

class Data(Base):
	__tablename__ = "data"
	sid = Column(Integer, primary_key=True)
	cid = Column(Integer, primary_key=True)
	data_payload = Column(Text)

class Sensor(Base):
	__tablename__ = "sensor"
	sid = Column(Integer, primary_key=True)
	hostname = Column(Text)
	interface = Column(Text)
	filter = Column(DateTime)
	detail = Column(SmallInteger)
	encoding = Column(SmallInteger)
	last_cid = Column(Integer)
	
	def __repr__(self):
		return "<Sensor ('%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sid, self.hostname, self.interface, self.filter, self.detail, self.encoding, self.last_cid)

class Signature(Base):
	__tablename__ = "signature"
	sig_id = Column(Integer, primary_key=True)
	sig_name = Column(String(255))
	sig_class_id = Column(Integer)
	sig_priority = Column(Integer)
	sig_rev = Column(Integer)
	sig_sid = Column(Integer)
	sig_gid = Column(Integer)

	def __repr__(self):
		return "<Signature ('%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sig_id, self.sig_name, self.sig_class_id, self.sig_priority, self.sig_rev, self.sig_sid, self.sig_gid)

class IpHdr(Base):
	__tablename__ = "iphdr"
	sid = Column(Integer, primary_key=True)
	cid = Column(Integer, primary_key=True)
	ip_src = Column(Integer)
	ip_dst = Column(Integer)
	ip_ver = Column(SmallInteger)
	ip_hlen = Column(SmallInteger)
	ip_tos = Column(SmallInteger)
	ip_len = Column(SmallInteger)
	ip_id = Column(SmallInteger)
	ip_flags = Column(SmallInteger)
	ip_off = Column(SmallInteger)
	ip_ttl = Column(SmallInteger)
	ip_proto = Column(SmallInteger)
	ip_csum = Column(SmallInteger)

	def __repr__(self):
		return "<IpHdr ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sid, self.cid, self.ip_src, self.ip_dst, self.ip_ver, self.ip_hlen, self.ip_tos, self.ip_len, self.ip_id, self.ip_flags, self.ip_off, self.ip_ttl, self.ip_proto, self.ip_csum)

class IcmpHdr(Base):
	__tablename__ = "icmphdr"
	sid = Column(Integer, primary_key=True)
	cid = Column(Integer, primary_key=True)
	icmp_type = Column(SmallInteger)
	icmp_code = Column(SmallInteger)
	icmp_csum = Column(SmallInteger)
	icmp_id = Column(SmallInteger)
	icmp_seq = Column(SmallInteger)

	def __repr__(self):
		return "<IcmpHdr ('%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sid, self.cid, self.icmp_type, self.icmp_code, self.icmp_csum, self.icmp_id, self.icmp_seq)

class TcpHdr(Base):
	__tablename__ = "tcphdr"
	sid = Column(Integer, primary_key=True)
	cid = Column(Integer, primary_key=True)
	tcp_sport = Column(SmallInteger)
	tcp_dport = Column(SmallInteger)
	tcp_seq = Column(Integer)
	tcp_ack = Column(Integer)
	tcp_off = Column(SmallInteger)
	tcp_res = Column(SmallInteger)
	tcp_flags = Column(SmallInteger)
	tcp_win = Column(SmallInteger)
	tcp_csum = Column(SmallInteger)
	tcp_urp = Column(SmallInteger)

	def __repr__(self):
		return "<TcpHdr ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sid, self.cid, self.tcp_sport, self.tcp_dport, self.tcp_seq, self.tcp_ack, self.tcp_off, self.tcp_res, self.tcp_flags, self.tcp_win, self.tcp_csum, self.tcp_urp)

class UdpHdr(Base):
	__tablename__ = "udphdr"
	sid = Column(Integer, primary_key=True)
	cid = Column(Integer, primary_key=True)
	udp_sport = Column(SmallInteger)
	udp_dport = Column(SmallInteger)
	udp_len = Column(SmallInteger)
	udp_csum = Column(SmallInteger)

	def __repr__(self):
		return "<UdpHdr ('%s', '%s', '%s', '%s', '%s', '%s')>" % (self.sid, self.cid, self.udp_sport, self.udp_dport, self.udp_len, self.udp_csum)
		
class Event(Base):
	__tablename__ = "event"
	sid = Column(
		Integer,
		ForeignKey(Sensor.sid),
		ForeignKey(IpHdr.sid),
		ForeignKey(IcmpHdr.sid),
		ForeignKey(TcpHdr.sid),
		ForeignKey(UdpHdr.sid),
		ForeignKey(Data.sid),
		primary_key=True)
	cid = Column(
		Integer,
		ForeignKey(IpHdr.cid),
		ForeignKey(IcmpHdr.cid),
		ForeignKey(TcpHdr.cid),
		ForeignKey(UdpHdr.cid),
		ForeignKey(Data.cid),
		primary_key=True)
	signature = Column(Integer, ForeignKey(Signature.sig_id))
	timestamp = Column(DateTime)
	
	sensor = relation(Sensor, backref='events')
	iphdr = relation(IpHdr, backref='event', primaryjoin=and_(sid==IpHdr.sid, cid==IpHdr.cid))
	icmphdr = relation(IcmpHdr, backref='event', primaryjoin=and_(sid==IcmpHdr.sid, cid==IcmpHdr.cid))
	tcphdr = relation(TcpHdr, backref='event', primaryjoin=and_(sid==TcpHdr.sid, cid==TcpHdr.cid))
	udphdr = relation(UdpHdr, backref='event', primaryjoin=and_(sid==UdpHdr.sid, cid==UdpHdr.cid))
	data = relation(Data, backref='event', primaryjoin=and_(sid==Data.sid, cid==Data.cid))
	signatureObj = relation(Signature, backref='events', primaryjoin=signature == Signature.sig_id)
	
	def __repr__(self):
		return "<Event ('%s', '%s', '%s', '%s')>" % (self.sid, self.cid, self.signature, self.timestamp)

class DbConversion():
	engine = 'mysql'
	
	def __init__(self, engine):
		if engine == "mysql" or engine == "postgresql":
			self.engine = engine
	
	def subdays(self, days):
		if self.engine == "mysql":
			return func.subdate(func.now(), days)
		if self.engine == "postgresql":
			return func.current_timestamp() - text("INTERVAL '" + str(days) + " day'")
			
	def date_output(self, t):
		if self.engine == "mysql":
			return func.date_format(t, '%m/%d')
		if self.engine == "postgresql":
			return func.to_char(t, 'MM/DD')

	def date_compare(self, t):
		if self.engine == "mysql":
			return func.date_format(t, '%Y-%m-%d')
		if self.engine == "postgresql":
			return func.to_timestamp(func.to_char(t, 'YYYY-MM-DD'), 'YYYY-MM-DD')

	def date_time_to_timestamp(self, t):
		if self.engine == "mysql":
			return t
		if self.engine == "postgresql":
			return func.to_timestamp(t, 'YYYY-MM-DD HH24:MI')
