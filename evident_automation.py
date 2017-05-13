from __future__ import print_function
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from subprocess import Popen, PIPE
from esp_sdk import configuration
from jira import JIRA
import simplejson
import traceback
import requests #to disable warnings
import esp_sdk
import sqlite3
import shutil
import json
import time
import sys
import os

requests.packages.urllib3.disable_warnings()

configuration.access_key_id = access_key
configuration.secret_access_key = secret_key

def cleanup():
	Popen("./cleanup.sh")
	print("cleaning up")

def find_shift():
	date = time.asctime()[0:11]
	hour = int(time.asctime()[11:13])
	if hour == 23: 
		return (date, 'Swing', 65)
	elif hour == 15: 
		return (date, 'Morning', 65)
	else: 
		return (date, 'Night', 102)


'ONLY CHECKS DEFAULT SIGNATURES.  WILL NEED TO ADD SUPPORT IF WE START USING CUSTOM SIGNATURES'
class Evident():
	def __init__(self):
		#each signature link has a unique link number e.g. /reports/signature/137
		# I took out the unique sig numbers in the links and put them here to reduce API calls
		#signature_number:remediation_time
		self.valid_signatures = {51:1,52:1,45:1,41:1,48:1,49:1,39:1,42:1,36:1,
								37:1,38:1,43:1,44:1,35:1,46:1,47:1,22:1,108:1,
								126:1,124:1,95:1,103:1,90:1,105:1,92:1,102:1,
								94:1,104:1,93:1,84:3,96:3,50:3,56:3,55:3,54:3,
								53:3,34:3,1:3,67:3,5:3,85:3,106:3,109:3,123:3,
								28:3,29:3,137:3,27:3}
		#each region link has a unique link number e.g. /alerts/region/14
		#I took out the unique region numbers in the links and put them here to reduce API calls
		#region_number:region_name
		self.regions = {'15':'eu_west_2', '14':'ca_central_1', '13':'us_east_2', '12':'ap_south_1',
					'11':'ap_northeast_2', '10':'eu_central_1', '9':'global', '8':'us_west_2', 
					'7':'us_west_1', '6':'us_east_1', '5':'sa_east_1', '4':'eu_west_1', 
					'3':'ap_southeast_2', '2':'ap_southeast_1', '1':'ap_northeast_1'}
		self.external_accounts = {}
		#signatures json file has been saved to disk to reduce the amoount of API calls made
		#I can query the entire JSON file instead of making individual API calls
		self.signatures = simplejson.load(open('signatures.json'))
		self.db = Database()
		self.api_client = esp_sdk.ApiClient()
		self.report_filter = '?filter[created_at_gt]={}&page[size]=100'.format(self.get_timestamp())
		self.alerts_filter = '?filter[status_eq]=fail&page[size]=100'
		self.duplicate_alerts = set()
		self.counts = {'Current_Alerts':0, 'SGRC_Escalations':0, 'Fixed_Alerts':0, 'Total_Alerts':0, 'Duplicate_Alerts':0}

	def get_reports(self):		
		#reports are paginated, we have to visit each page separately
		#try/catch around all REST calls due to rate limiting - won't need to resend the previous calls
		current = 'https://api.evident.io/api/v2/reports' + self.report_filter
		links = self.get_first_link('https://api.evident.io/api/v2/reports'+self.report_filter)
		
		#getting the last link, if no last link then there is only 1 page
		if 'last' in links.keys(): #99% sure this will 100% be true
			report_links_last = links['last']
		else:
			report_links_last = current

		#TODO: should be while current != report_links_last:, but I don't wanna test it right now...
		while True:
			print("REPORT: " + current)
			reports = self.get_(current+self.report_filter)
			while reports == None: #rate-limit safeguard
				reports = self.get_(current+self.report_filter)	

			for report in reports['data']:
				self.get_alerts(report)

			if current == report_links_last:
				print("LAST REPORT PAGE: " + current)
				break
			else:
				current = reports['links']['next']

	def get_alerts(self, report):
		#alerts are paginated, we have to visit each page separately
		#try/catch around all REST calls due to rate limiting - won't need to resend the previous calls
		current_alert = report['relationships']['alerts']['links']['related']
		print('\tALERT: ' + current_alert)

		alert_links = self.get_first_link(report['relationships']['alerts']['links']['related']+self.alerts_filter)
		while alert_links == None: #rate-limit safeguard
			alert_links = self.get_first_link(report['relationships']['alerts']['links']['related']+self.alerts_filter)

		#if there is no last link then there is only 1 page - set last page to current page
		if 'last' in alert_links.keys():
			alert_links_last = alert_links['last']
		else:
			alert_links_last = report['relationships']['alerts']['links']['related']

		#TODO: should be while current_alert != alert_links_last:, but I don't wanna test it right now...
		print('\t\tITERATING THROUGH ALERT PAGES')
		while True:
			alerts = self.get_(current_alert+self.alerts_filter)
			while alerts == None: #rate-limit safeguard
				alerts = self.get_(current_alert+self.alerts_filter)
			
			for alert in alerts['data']:
				self.get_alert_data(alert)

			if current_alert == alert_links_last:
				break
			else:
				current_alert = alerts['links']['next']

	def get_alert_data(self, alert):
		signature_number = int(str(alert['relationships']['signature']['links']['related']).split('/')[-1].split('.')[0])

		if signature_number in self.valid_signatures.keys():
			signature = None
			#find signature information in json file
			for sig in self.signatures['data']:
				if sig['id'] == str(signature_number):
					signature = sig

			external_account = self.get_external_account(alert['relationships']['external_account']['links']['related'])
			while external_account == None: #rate-limit safeguard
				external_account = self.get_external_account(alert['relationships']['external_account']['links']['related'])

			sig = (alert['attributes']['resource'], signature['attributes']['name'], external_account, str(datetime.now())[0:10], self.valid_signatures[signature_number])

			if sig not in self.duplicate_alerts:
				self.duplicate_alerts.add(sig)
				self.counts['Total_Alerts'] += 1

				database_containing_row = self.db.add_row_no_duplicates(sig, 'Current_Alerts')
				data = [alert['attributes']['started_at'], alert['attributes']['resource'],external_account[0],external_account[1],
						signature['attributes']['name'], alert['attributes']['status'], self.regions[str(alert['relationships']['region']['links']['related']).split('/')[-1].split('.')[0]], 
						str(self.valid_signatures[signature_number]) + ' days', signature['attributes']['resolution']]

				if database_containing_row == None:
					self.counts['Current_Alerts'] += 1
					self.write_to_csv(data, external_account[0])
				elif database_containing_row == 'Current_Alerts':
					if self.db.check_remediation_time(sig, database_containing_row):
						self.counts['SGRC_Escalations'] += 1
						self.write_to_csv(data, 'SGRC_Escalations')
					self.counts['Duplicate_Alerts'] += 1
					
	def get_first_link(self, url):
		try:
			return json.loads(self.api_client.request('GET', url).data)['links']
		except:
			print('rate limit reached in get_first_link. Waiting...')
			time.sleep(10)

	def get_(self, current):
		try:
			return json.loads(self.api_client.request('GET', current).data)
		except:
			print("rate limit reached in GET request. Waiting...")
			time.sleep(10)

	def get_external_account(self, url):
		ea_number = int(url.split('/')[-1].split('.')[0])

		#I left the external account API call in because it seems like it can change over time
		#external account/ARN are retrieved through an API call once, then saved for later
		if ea_number in self.external_accounts.keys():
			return self.external_accounts[ea_number]
		else:
			try:
				external_account = json.loads(self.api_client.request('GET', url).data)
				account = (external_account['data']['attributes']['name'], external_account['data']['attributes']['arn'])
				self.external_accounts[ea_number] = account
				return account

			except:
				print("rate limit reached in get_external_account. Waiting...")
				time.sleep(10)
				return None

	def write_to_csv(self, row, account):
		if not os.path.exists('evident_reports'):
			try:
				os.makedirs('evident_reports')
			except OSError as exc:
				raise
		filename = 'evident_reports/' + account + '_evident_report_' + str(datetime.now().strftime('%Y.%m.%d')) + '.csv'
		with open(filename, 'a+') as csv:
			if os.stat(filename).st_size == 0:
				csv.write(self.get_headers(account))
			csv.write(','.join(row) + '\n')

	def write_fixed_alerts(self):
		fixed_alerts = self.db.remove_fixed_alerts()
		for row in fixed_alerts:
			to_print = [str(x) for x in row[0:4]]
			to_print = [str(row[4]),str(datetime.now().strftime('%Y.%m.%d'))] + to_print
			self.write_to_csv(to_print, 'Fixed_Alerts')
		self.counts['Fixed_Alerts'] = len(fixed_alerts)		

	#timestamp -8 hours. in UTC
	def get_timestamp(self):
		return (datetime.utcnow() - timedelta(hours=8)).isoformat().replace('T', '+')[0:19]

	def get_headers(self, account):
		if account == 'Fixed_Alerts':
			return 'Alert Date,Fixed Time,Resource,Signature Name,External Team,ARN\n'
		else:
			return "Time,Resource,External Team,ARN,Signature Name,Status,Region,Remediation Time,Remediation\n"


#TODO: cleanup all these fucking cursors
class Database():
	def __init__(self):
		self.database = sqlite3.connect('evident.db')

	def vacuum(self):
		#remove empty space, defragment, align table, make contiguous
		print('DB: Vacuuming')
		self.database.execute('VACUUM')

	def add_row_no_duplicates(self, row, db):
		with self.database:
			cursor = self.database.cursor()
			if not self.check_if_row_exists(row, 'Current_Alerts'): 
				if not self.check_if_row_exists(row, 'SGRC_Escalations'):
					self.add_row(row, db)
					return None
				else:
					self.set_dirty(row, db)
					return 'SGRC_Escalations'
			else:
				self.set_dirty(row, db)
				return 'Current_Alerts'

	def set_dirty(self, row, db):
		try:
			with self.database:
				cursor = self.database.cursor()
				cursor.execute("UPDATE {} SET Dirty=1 WHERE Resource='{}' and Name='{}'".format(db, row[0], row[1]))
		except:
			print('ERROR: {}: dirty bits not set after {}'.format(db, row))

	def add_row(self, row, db):
		try:
			with self.database:
				cursor = self.database.cursor()
				#data coming directly from Evident.IO, no need to sanitize
				#TEXT fields must be contained in ' '
				cursor.execute("INSERT INTO {} VALUES('{}', '{}', '{}', '{}', '{}', {}, {})".format(db, row[0], row[1], row[2][0], row[2][1], row[3], row[4], 1))
		except:
			print('ERROR: {}: unable to add row\n{}'.format(db, row))

	#TODO: entries with no data (1,) is seen as a duplicate entry
	def check_if_row_exists(self, row, db):
		with self.database:
			cursor = self.database.cursor()

			cursor.execute("SELECT 1 FROM {} WHERE Resource='{}' AND Name='{}' LIMIT 1".format(db, row[0], row[1]))
			data = cursor.fetchone()

			if data is None:
				return False
			return True

	def remove_fixed_alerts(self):
		ret = []
					
		with self.database:
			cursor = self.database.cursor()
			for table in ('Current_Alerts', 'SGRC_Escalations'):
				cursor.execute("SELECT * FROM {}".format(table))
				rows = cursor.fetchall()
				
				try:
					for row in rows:		
						if row[6] == 0:
							cursor.execute("INSERT INTO Fixed_Alerts SELECT Resource,Name,External_Account,ARN,Alert_Date,Remediation_Time,'{}' FROM {} where Resource='{}' and Name='{}'".format(datetime.now(), table, row[0], row[1]))
							cursor.execute("DELETE FROM {} WHERE Resource='{}' and Name='{}'".format(table, row[0], row[1]))
							ret.append(row)
				except:
					print('ERROR: {}: fixed alerts not removed after {}'.format(table, row))
					traceback.print_exc()
		return ret

	def reset_dirty(self):
			with self.database:
				cursor = self.database.cursor()
				try:
					for table in ('Current_Alerts','SGRC_Escalations'):
						cursor.execute("UPDATE {} SET Dirty=0".format(table))
				except:
					print('ERROR: {}: dirty bits not reset'.format(db))

	def check_remediation_time(self, row, db):
		with self.database:
			cursor = self.database.cursor()

			cursor.execute("SELECT Alert_Date FROM {} where Resource='{}' and Name='{}'".format(db, row[0], row[1]))
			row_timestamp = int(time.mktime(time.strptime(cursor.fetchone()[0].strip(), '%Y-%m-%d')))
			current_timestamp = int(time.time())
	
			if current_timestamp - row_timestamp > (int(row[4])+1)*24*60*60: #if delta time is greater than remediation time
				cursor.execute("INSERT INTO SGRC_Escalations SELECT Resource,Name,External_Account,ARN,Alert_Date,Remediation_Time,{} FROM Current_Alerts where Resource='{}' and Name='{}'".format(1, row[0], row[1]))
				cursor.execute("DELETE FROM Current_Alerts WHERE Resource='{}' and Name='{}'".format(row[0], row[1]))
				return True
			return False

	def reset_db(self):
		with self.database:
			cursor = self.database.cursor()

			cursor.execute("DROP TABLE Current_Alerts")
			cursor.execute("DROP TABLE Fixed_Alerts")
			cursor.execute("DROP TABLE SGRC_Escalations")
			cursor.execute("CREATE TABLE Fixed_Alerts(Resource TEXT, Name TEXT,  External_Account TEXT, ARN TEXT, Alert_Date TEXT, Remediation_Time TEXT, Remediation_Date TEXT, PRIMARY KEY(Resource, Name, Remediation_Date))")
			cursor.execute("CREATE TABLE Current_Alerts(Resource TEXT, Name TEXT,  External_Account TEXT, ARN TEXT, Alert_Date TEXT, Remediation_Time TEXT, Dirty INT, PRIMARY KEY(Resource, Name))")
			cursor.execute("CREATE TABLE SGRC_Escalations(Resource TEXT, Name TEXT,  External_Account TEXT, ARN TEXT, Alert_Date TEXT, Remediation_Time TEXT, Dirty INT, PRIMARY KEY(Resource, Name))")


class Jira():
	def __init__(self):
		jira_options = { 'server': jira.com, 'verify': False }	
		try:
			self.jira = JIRA(options=jira_options, basic_auth=(username, password))
			self.jira._session.proxies={'http':proxy.com, 'https':proxy.com}
		except:
			eprint("ERROR: cannot create JIRA object.  Is Jira down?")
			traceback.print_exc()
		self.ticket = None

	#@ret: (Fri Feb  3, 'Night', Shaver)
	def find_shift(self):
		date = time.asctime()[0:11]
		hour = int(time.asctime()[11:13])
		if hour >= 16 and hour < 23: 
			return (date, 'Swing')
		elif hour >= 8 and hour < 16: 
			return (date, 'Morning')
		else: 
			return (date, 'Night')

	def create_ticket(self):
		date = self.find_shift()
		summary = "evident.IO new alerts for " + date[1] + ' ' + date[0]
		jira_payload = {
						'project' : {'key' : team},
						'issuetype' : {'name' : 'Other'},
						'customfield_11802' : 	{ #This is the "Requesting Team"
												'id' : id_num,	#this is needed
												'key' : team,	#this is also needed
												'name' : team_name
												},
						'summary' : summary,
						'description': "Evident.IO new alerts for " + date[1] + " " + date[0]
						}
		try:
			new_ticket = self.jira.create_issue(fields=jira_payload)
			self.ticket = new_ticket.key
			print("created ticket: " + new_ticket.key)
		except:
			print("ERROR: cannot create new jira ticket")
			traceback.print_exc()

	def add_attachment(self):
		shutil.make_archive('evident_reports', 'zip', 'evident_reports')
		
		try:
			with open('evident_reports.zip', 'rb') as ifile:
				self.jira.add_attachment(self.ticket, ifile)
				print( self.ticket + ': attaching zipped reports directory')
		except:
			print("ERROR: unable to add zipped reports directory to ticket " + self.ticket)
			traceback.print_exc()


class Email: #TODO: I should just make this a module...
	def __init__(self):
		self.shift = find_shift()

	def send_email(self):
		message = MIMEMultipart('alternative')
		message['Subject'] = "Evident.IO Alerts " + self.shift[1] + ' ' + self.shift[0]
		message['To'] = to@email.com
		message['From'] = from@email.com

		#adding attachments
		shutil.make_archive('evident_reports', 'zip', 'evident_reports')
		try:
			with open('evident_reports.zip', 'rb') as ifile:
				print('Email: attaching zip')
				attachment = MIMEApplication(ifile.read(), Name='evident_reports.zip')
				attachment['Content-Disposition'] = 'attachment; filename="evident_reports.zip"'
				message.attach(attachment)
		except:
			print("ERROR: unable to attach zip to email")
			traceback.print_exc()

		print("Sending Email")
		try:
			process = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin = PIPE) #-t reads message for recipients. -oi ignores single dots on lines by themselves
			process.communicate(message.as_string())
		except:
			print('ERROR: Unable to send email')
			traceback.print_exc()


class Test(Evident):
	def __init__(self):
		Evident.__init__(self)
		self.database = Database()
		self.jira = Jira()

	def test_all(self):
		self.get_reports()
		self.db.reset_dirty()

		#new timestamp for > 1 hour
		print("CHANGING REPORT FILTER")
		self.duplicate_alerts = set()
		self.counts = {'Current_Alerts':0, 'SGRC_Escalations':0, 'Fixed_Alerts':0, 'Total_Alerts':0, 'Duplicate_Alerts':0}
		
		self.report_filter = '?filter[created_at_gt]=' + self.get_new_timestamp() + '&page[size]=100'
		self.test_check_remediation_time()
		self.get_reports()

		self.write_fixed_alerts()
		self.db.reset_dirty()
		self.db.vacuum()
		print(self.counts)

	def test_SGRC_Escalations(self):
		self.test_check_remediation_time()
		self.get_reports()

		self.write_fixed_alerts()
		self.db.reset_dirty()
		self.db.vacuum()
		print(self.counts)

	def test_check_remediation_time(self):
		with self.database.database:
			cursor = self.database.database.cursor()
			cursor.execute("UPDATE Current_Alerts SET Alert_Date='{}' WHERE rowid<=50".format('2017-04-10'))

	def test_Current_Alerts_to_Fixed_Alerts(self):
		#reinitialize database, get reports > 3 hours, reset dirt, get reports > 1.
		#all reports > 2 hours should go to Fixed_Alerts
		self.get_reports()
		self.db.reset_dirty()

		#new timestamp for > 1 hour
		print("CHANGING REPORT FILTER")
		self.duplicate_alerts = set()
		self.counts = {'Current_Alerts':0, 'SGRC_Escalations':0, 'Fixed_Alerts':0, 'Total_Alerts':0, 'Duplicate_Alerts':0}
		
		self.report_filter = '?filter[created_at_gt]=' + self.get_timestamp() + '&page[size]=100'
		self.get_reports()
		self.remove_fixed_alerts()
		self.db.reset_dirty()
		self.db.vacuum()

	def test_SGRC_Escalations_to_Fixed_Alerts(self):
		self.db.reset_db();
		self.get_reports()
		self.db.reset_dirty()
		self.Current_to_SGRC_all_rows()

		print("CHANGING REPORT FILTER")
		self.duplicate_alerts = set()
		#new timestamp for > 1 hour
		self.report_filter = '?filter[created_at_gt]=' + self.get_timestamp() + '&page[size]=100'
		self.get_reports()
		self.remove_fixed_alerts()

	def test_get_reports(self):
		self.db.reset_db()
		while True:
			self.get_reports()
			self.write_fixed_alerts()
			self.db.reset_dirty()
			self.duplicate_alerts = set()
			with open("get_reports_log.txt", "a+") as ofile:
				ofile.write(str(datetime.now())+'\n')
				for key in self.counts.keys():
					ofile.write(str(key) + ':' + str(self.counts[key]) + '\n')
				ofile.write('\n')
			print(self.counts)
			self.counts = {'Current_Alerts':0, 'SGRC_Escalations':0, 'Fixed_Alerts':0, 'Total_Alerts':0, 'Duplicate_Alerts':0}

	def Current_to_SGRC(self):
		with self.database.database:
			cursor = self.database.database.cursor()
			cursor.execute("INSERT INTO SGRC_Escalations SELECT * FROM Current_Alerts")
			cursor.execute("DELETE FROM Current_Alerts")
		self.reset_dirty_SGRC_Escalations()

	def SGRC_to_Current(self):
		with self.database.database:
			cursor = self.database.database.cursor()
			cursor.execute("INSERT INTO Current_Alerts SELECT * FROM SGRC_Escalations")
			cursor.execute("DELETE FROM SGRC_Escalations")
		self.reset_dirty_Current_Alerts()

	def reset_dirty_Current_Alerts(self):
		with self.database.database:
			cursor = self.database.database.cursor()
			cursor.execute("UPDATE Current_Alerts SET Dirty=0")

	def reset_dirty_SGRC_Escalations(self):
		with self.database.database:
			cursor = self.database.database.cursor()
			cursor.execute("UPDATE SGRC_Escalations SET Dirty=0")

	def get_new_timestamp(self):
		return (datetime.utcnow() - timedelta(hours=1)).isoformat().replace('T', '+')[0:19]


def main():
	
	evident = Evident()
	evident.get_reports()
	evident.write_fixed_alerts()
	evident.db.reset_dirty()
	evident.db.vacuum()
	
	if (evident.counts['Current_Alerts'] != 0 or evident.counts['SGRC_Escalations'] != 0 or evident.counts['Fixed_Alerts'] != 0):
		email = Email()
		email.send_email()


		#if we ever decide to do this through Jira
		'''
		jira = Jira()
		jira.create_ticket()
		jira.add_attachment()
		'''

	cleanup()

if __name__=='__main__':
	main()

#	email = Email()
#	email.send_email()
#	evident = Evident()
#	evident.db.reset_db()
#	evident.db.vacuum()
#	evident.get_reports()
#	evident.db.reset_dirty()
#	cleanup()

#	test = Test()
#	test.test_all()
#	test.test_SGRC_Escalations()
#	test.db.reset_dirty()
#	test.test_get_reports()
#	test.test_Current_Alerts_to_Fixed_Alerts()
#	test.test_SGRC_Escalations_to_Fixed_Alerts()
#	test.reset_dirty_Current_Alerts();
#	test.test_check_remediation_time()
#	test.SGRC_to_Current()


