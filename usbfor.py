import glib
import sys
import os
import argparse
import subprocess
import time
import json
import hashlib
try:
	import pyudev
	from pyudev import Context, Monitor
	from pyudev.glib import MonitorObserver
except ImportError:
	print "Missing required library pyudev"
try:
	import pytsk3
except ImportError:
	print "Missing required library pytsk"

def recursive_extract(dirObject, parentPath, img, name):

	#recursively move through the image filesystem
	for begin in dirObject:
		if begin.info.name.name in [".", ".."]:
			continue

		try:					#try and grab the type of file
			f_type = begin.info.meta.type
		except:
			print "Cannot retrieve type of",begin.info.name.name
			continue

		try:					#Traverse the filesystem
			filepath = '/{0}/{1}'.format('/'.join(parentPath),begin.info.name.name)
			outputPath ='./{0}/{1}/'.format("Carved_files_{0}".format(name),'/'.join(parentPath))

			if f_type == pytsk3.TSK_FS_META_TYPE_DIR:		#if directory traverse into it
				sub_directory = begin.as_directory()
				parentPath.append(begin.info.name.name)
				recursive_extract(sub_directory,parentPath,img,name)
				parentPath.pop(-1)
				print "Directory: {0}".format(filepath)

			elif f_type == pytsk3.TSK_FS_META_TYPE_REG and begin.info.meta.size != 0:	#if file and size > 1
				filedata = begin.read_random(0,begin.info.meta.size)

				print "Extracting File : " + str(['/'.join(parentPath)+begin.info.name.name])
					
				#create new folder to extract the file
				if not os.path.exists(outputPath):
					os.makedirs(outputPath)

				#extract the file
				extractFile = open(outputPath+begin.info.name.name,'w')
				extractFile.write(filedata)
				extractFile.close

			#if file but file size is 0 
			elif f_type == pytsk3.TSK_FS_META_TYPE_REG and begin.info.meta.size == 0:
				print "Unable to recover : " + str(['/'.join(parentPath)+begin.info.name.name])

		except IOError as e:
			print e
			continue


def get_information(device):
	print "USB DETECTED : \n"
	print "Name : {0} ".format(device.sys_name)
	print "Type : {0}".format(device.device_type)
	print "Run Directory : {0}".format(device.context.run_path)
	print "Time since initialized : {0} ".format(device.time_since_initialized)
	print 'Background event {0}: {1}'.format(device.action,device.device_path)
	print 'Bus Type : {0}'.format(device.get('ID_BUS'))
	print 'Partition Label : {0}'.format(device.get('ID_FS_LABEL'))
	print 'FileSystem : {0}'.format(device.get('ID_FS_TYPE'))
	print 'USB Driver : {0}'.format(device.get('ID_USB_DRIVER'))
	print 'Vendor : {0}'.format(device.get('ID_VENDOR_FROM_DATABASE'))
	print ""
	
	if args.r is True:
		report += "USB DETECTED : \n"
		report += "Name : {0}\n".format(device.sys_name)
		report += "Type : {0}\n".format(device.device_type)
		report += "Run Directory : {0}\n".format(device.context.run_path)
		report += "Time since initialized : {0}\n".format(device.time_since_initialized)
		report += 'Background event {0}: {1}\n'.format(device.action,device.device_path)
		report += 'Bus Type : {0}\n'.format(device.get('ID_BUS'))
		report += 'Partition Label : {0}\n'.format(device.get('ID_FS_LABEL'))
		report += 'FileSystem : {0}\n'.format(device.get('ID_FS_TYPE'))
		report += 'USB Driver : {0}\n'.format(device.get('ID_USB_DRIVER'))
		report += 'Vendor : {0}\n'.format(device.get('ID_VENDOR_FROM_DATABASE'))

def device_event(observer, device):			#get more information
	
	#print all usb_add events
	if device.action == "add":				#only if its a usb add event
		g['acid_{0}'.format(device.get('ID_FS_LABEL'))] = []
		get_information(device)				#function to print usb information
		#Create image of USB device
		if device.get('ID_FS_LABEL') is not None:
			#carve all files from USB partition
			imghandle = pytsk3.Img_Info("/dev/{0}".format(device.sys_name))
			filesystemObject = pytsk3.FS_Info(imghandle)
			dirObject = filesystemObject.open_dir(path="/")
			recursive_extract(dirObject,[],"/dev/{0}".format(device.sys_name),device.get('ID_FS_LABEL'))
			print "[+] Completed carving files from image"
			
			#submit carved files to cuckoo
			print "[+] Submitting all files found to Cuckoo"
			listpid = subprocess.Popen(['./cuckoo/utils/submit.py','Carved_files_{0}/'.format(device.get('ID_FS_LABEL'))],stdout=subprocess.PIPE)
			stoutlist = listpid.communicate()
			if stoutlist is not None:
				for cpid in stoutlist[0].split('\n'):
					print cpid
					g['acid_{0}'.format(device.get('ID_FS_LABEL'))].append(cpid.split(' ')[-1])
			g['acid_{0}'.format(device.get('ID_FS_LABEL'))].pop()
			while True:
				if os.path.exists("cuckoo/storage/analyses/{0}/".format(g['acid_{0}'.format(device.get('ID_FS_LABEL'))][-1])):
					print "[*] Summary"
					print "Assesed Files : {0}".format(len(g['acid_{0}'.format(device.get('ID_FS_LABEL'))]))
					if args.r is True:
						report = "[*] Summary\nAssesed Files : {0}\n----------------------\n".format(len(g['acid_{0}'.format(device.get('ID_FS_LABEL'))]))
					get_information(device)
					for i in g['acid_{0}'.format(device.get('ID_FS_LABEL'))]:								#output assesment information
						if os.path.exists("cuckoo/storage/analyses/{0}/reports/".format(i)):
							try :
								rjsdata = None
								rjsdata = json.loads(open("cuckoo/storage/analyses/{0}/reports/report.json".format(i),'r').read())

								print 'Summarized Cuckoo report of file {0} given below.'.format(rjsdata['target']['file']['name'])
								print 'File : {0}'.format(rjsdata['target']['file']['name'])
								print 'Cuckoo id : {0}'.format(rjsdata['info']['id'])
								print 'Cuckoo score : {0}'.format(rjsdata['info']['score'])
								print 'File Type : {0}'.format(rjsdata['target']['file']['type'])
								print 'File Hash [SHA1] : {0}'.format(rjsdata['target']['file']['sha1'])
								print 'File Hash [MD5] : {0}'.format(rjsdata['target']['file']['md5'])
								print 'VirusTotal Summary : {0}'.format(rjsdata['virustotal']['summary'])
								print "Full Cuckoo report can be found at - cuckoo/storage/analyses/{0}/reports/\n".format(i)

								if args.r is True:
									report += 'Summarized Cuckoo report of file {0} given below.\n'.format(rjsdata['target']['file']['name'])
									report += 'File : {0}\n'.format(rjsdata['target']['file']['name'])
									report += 'Cuckoo id : {0}\n'.format(rjsdata['info']['id'])
									report += 'Cuckoo score : {0}\n'.format(rjsdata['info']['score'])
									report += 'File Type : {0}\n'.format(rjsdata['target']['file']['type'])
									report += 'File Hash [SHA1] : {0}\n'.format(rjsdata['target']['file']['sha1'])
									report += 'File Hash [MD5] : {0}\n'.format(rjsdata['target']['file']['md5'])
									report += 'VirusTotal Summary : {0}\n'.format(rjsdata['virustotal']['summary'])
									report += "Full Cuckoo report can be found at - cuckoo/storage/analyses/{0}/reports/\n\n".format(i)

							except ValueError:
								print '[-] Unable to parse the json report file. Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
								report += 'Full Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
							except KeyError:
								print '[-] Unable to parse the json report file. Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
								report += 'Full Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)

						if args.r is True:
							m =hashlib.md5()
							m.update(report)
							with open('Report-{0}.txt'.format(m.hexdigest()),'w') as rgen:
								rgen.write(report)
								rgen.close()
							print 'The Generated report can be found at - Report-{0}'.format(m.hexdigest())
					break


#Argparse configuration
parser = argparse.ArgumentParser(description='A USB Analysis tool')
parser.add_argument("-d", "--dd", dest='d', type=str, nargs='+', help='analyze a dd image of the USB Device')
parser.add_argument("-r", "--report", dest='r', action='store_true', help="Generate a report")
parser.add_argument("-c", "--clean", dest='c', action='store_true', help="Clean Cuckoo before starting tool")
args = parser.parse_args()

# a few initilizations
g = globals()
stat_info = os.stat("cuckoo/")		#find user's uid to appropriately call cuckoo
luid = stat_info.st_uid
lgid = stat_info.st_gid

if args.c is True:
	subprocess.call(['./cuckoo/cuckoo.py','--clean'])
if args.r is True:
	report = ""

pid = os.fork()
if pid == 0:
	try:
		if args.d is not None:
			for a in args.d:
				os.setgid(lgid)
				os.setuid(luid)				##statically set uid change to dynamic
				print '[+] Carving files from image'
				z = a.split('/')[-1]
				imghandle = pytsk3.Img_Info(a)
				filesystemObject = pytsk3.FS_Info(imghandle)
				dirObject = filesystemObject.open_dir(path="/")
				#recursive_extract(dirObject,[],a,z)
				g['acid_{0}'.format(z)] = []
				print "[+] Completed carving files from image"
				print "[+] Submitting all files found to Cuckoo"
				ddpid = subprocess.Popen(['./cuckoo/utils/submit.py','Carved_files_{0}/'.format(z)],stdout=subprocess.PIPE)
				stoutdd = ddpid.communicate()
				print "[+] Completed submitting files to cuckoo"
				for cpid in stoutdd[0].split('\n'):
					print cpid
					g['acid_{0}'.format(z)].append(cpid.split(' ')[-1])
				g['acid_{0}'.format(z)].pop()

				#print analysis information
				while True:
					if os.path.exists("cuckoo/storage/analyses/{0}/reports/".format(g['acid_{0}'.format(z)][-1])):
						print "[*] Summary"
						print "Assesed Files : {0}\n----------------------".format(len(g['acid_{0}'.format(z)]))
						if args.r is True:
							report = "[*] Summary\nAssesed Files : {0}\n----------------------\n".format(len(g['acid_{0}'.format(z)]))
						for i in g['acid_{0}'.format(z)]:								#output assesment information
							if os.path.exists("cuckoo/storage/analyses/{0}/reports/".format(i)):
								try :
									rjsdata = None
									rjsdata = json.loads(open("cuckoo/storage/analyses/{0}/reports/report.json".format(i),'r').read())

									print 'Summarized Cuckoo report of file {0} given below.'.format(rjsdata['target']['file']['name'])
									print 'File : {0}'.format(rjsdata['target']['file']['name'])
									print 'Cuckoo id : {0}'.format(rjsdata['info']['id'])
									print 'Cuckoo score : {0}'.format(rjsdata['info']['score'])
									print 'File Type : {0}'.format(rjsdata['target']['file']['type'])
									print 'File Hash [SHA1] : {0}'.format(rjsdata['target']['file']['sha1'])
									print 'File Hash [MD5] : {0}'.format(rjsdata['target']['file']['md5'])
									print 'VirusTotal Summary : {0}'.format(rjsdata['virustotal']['summary'])
									print "Full Cuckoo report can be found at - cuckoo/storage/analyses/{0}/reports/\n".format(i)

									if args.r is True:
										report += 'Summarized Cuckoo report of file {0} given below.\n'.format(rjsdata['target']['file']['name'])
										report += 'File : {0}\n'.format(rjsdata['target']['file']['name'])
										report += 'Cuckoo id : {0}\n'.format(rjsdata['info']['id'])
										report += 'Cuckoo score : {0}\n'.format(rjsdata['info']['score'])
										report += 'File Type : {0}\n'.format(rjsdata['target']['file']['type'])
										report += 'File Hash [SHA1] : {0}\n'.format(rjsdata['target']['file']['sha1'])
										report += 'File Hash [MD5] : {0}\n'.format(rjsdata['target']['file']['md5'])
										report += 'VirusTotal Summary : {0}\n'.format(rjsdata['virustotal']['summary'])
										report += "Full Cuckoo report can be found at - cuckoo/storage/analyses/{0}/reports/\n\n".format(i)

								except ValueError:
									print '[-] Unable to parse the json report file. Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
									report += 'Full Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
								except KeyError:
									print '[-] Unable to parse the json report file. Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
									report += 'Full Report can be found here - cuckoo/storage/analyses/{0}/reports/\n'.format(i)
						if args.r is True:
							m =hashlib.md5()
							m.update(report)
							with open('Report-{0}.txt'.format(m.hexdigest()),'w') as rgen:
								rgen.write(report)
								rgen.close()
							print 'The Generated report can be found at - Report-{0}'.format(m.hexdigest())
						sys.exit(0)

		if args.d is None:
			#Initialize the monitors to hook onto usb daemon
			context = Context()
			monitor = Monitor.from_netlink(context)

			monitor.filter_by(subsystem='block')
			observer = MonitorObserver(monitor)

			observer.connect('device-event', device_event)
			print '[*] Listening for USB Devices'
			monitor.start()
			glib.MainLoop().run()

	except KeyboardInterrupt:
		print "[*] Exiting tool"
else :
	try:
		os.setgid(lgid)
		os.setuid(luid)				##statically set uid change to dynamic
		print "[*] Starting Cuckoo Server"
		serverpid = subprocess.Popen('./cuckoo/cuckoo.py',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		serout,sererr = serverpid.communicate()

	except KeyboardInterrupt:
		print "[-] Stopping Cuckoo Server"
		sys.exit(1)
	except:
		print "[-] Unable to start Cuckoo Server"
		sys.exit(1)
