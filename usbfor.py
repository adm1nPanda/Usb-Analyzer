import glib
import sys
import os
import argparse
import subprocess
import time

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
				print "\n\nDirectory: {0}".format(filepath)

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
	
	#confirm if information is correct

def device_event(observer, device):			#get more information
	
	#print all usb_add events
	if device.action == "add":				#only if its a usb add event
		get_information(device)				#function to print usb information
		os.setegid(0)
		os.seteuid(0)
		#Create image of USB device
		if device.get('ID_FS_LABEL') is not None:
			if args.d == True:
				print '[+]Creating an image of this may take a while'
				with open("/dev/{0}".format(device.sys_name),'rb') as f:
					with open("image_{0}.dd".format(device.get('ID_FS_LABEL')), "wb") as i:
						i.write(f.read())
				print "[+]Completed imaging the USB Drive"
			
			#carve all files from USB partition
			imghandle = pytsk3.Img_Info("/dev/{0}".format(device.sys_name))
			filesystemObject = pytsk3.FS_Info(imghandle)
			dirObject = filesystemObject.open_dir(path="/")
			recursive_extract(dirObject,[],"/dev/{0}".format(device.sys_name),device.get('ID_FS_LABEL'))
			print "[+] Completed carving files from image"
			
			#submit carved files to cuckoo
			os.setegid(lgid)
			os.seteuid(luid)				##statically set uid change to dynamic
			print "[+] Submitting all files found to Cuckoo"
			listpid = subprocess.Popen(['./cuckoo/utils/submit.py','Carved_files_{0}/'.format(device.get('ID_FS_LABEL'))],stdout=subprocess.PIPE)
			stoutlist = listpid.communicate()
			if stoutlist is not None:
				for cpid in stoutlist[0].split('\n'):
					print cpid
					acid.append(cpid.split(' ')[-1])
			acid.pop()
			time.sleep(5*len(acid))
			if os.path.exists("cuckoo/storage/analyses/{0}/".format(acid[-1])):
				print "[*] Summary"
				print "Assesed Files : {0}".format(len(acid))
				for i in acid:								#output assesment information
					print "Cuckoo Report can be found at - cuckoo/storage/analyses/{0}/".format(i)


#Argparse configuration
parser = argparse.ArgumentParser(description='A USB Analysis tool')
parser.add_argument("-d", "--dd", dest='d', type=str, nargs='+', help='analyze a dd image of the USB Device')
parser.add_argument("-r", "--report", dest='r', action='store_true', help="Generate a report")
parser.add_argument("-c", "--clean", dest='c', action='store_true', help="Clean Cuckoo before starting tool")
args = parser.parse_args()

# a few initilizations
acid = []		#list to keep track of cuckoo id of files analysed
stat_info = os.stat("cuckoo/")
luid = stat_info.st_uid
lgid = stat_info.st_gid

if args.c is True:
	subprocess.call(['./cuckoo/cuckoo.py','--clean'])

pid = os.fork()
if pid == 0:
	try:
		if args.d is not None:
			for a in args.d:
				os.setegid(lgid)
				os.seteuid(luid)				##statically set uid change to dynamic
				print '[+] Carving files from image'
				imghandle = pytsk3.Img_Info(a)
				filesystemObject = pytsk3.FS_Info(imghandle)
				dirObject = filesystemObject.open_dir(path="/")
				recursive_extract(dirObject,[],a,a)
				print "[+] Completed carving files from image"
				print "[+] Submitting all files found to Cuckoo"
				ddpid = subprocess.Popen(['./cuckoo/utils/submit.py','Carved_files_{0}/'.format(a)],stdout=subprocess.PIPE)
				stoutdd = ddpid.communicate()
				if stoutdd is not None:
					for cpid in stoutdd[0].split('\n'):
						print cpid
						acid.append(cpid.split(' ')[-1])
				acid.pop()
				time.sleep(5*len(acid))
				if os.path.exists("cuckoo/storage/analyses/{0}/".format(acid[-1])):
					print "[*] Summary"
					print "Assesed Files : {0}".format(len(acid))
					for i in acid:								#output assesment information
						print "Cuckoo Report can be found at - cuckoo/storage/analyses/{0}/".format(i)
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
		os.setegid(lgid)
		os.seteuid(luid)				##statically set uid change to dynamic
		print "[*] Starting Cuckoo Server"
		serverpid = subprocess.Popen('./cuckoo/cuckoo.py',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		serverstout,serverster = serverpid.communicate()

	except KeyboardInterrupt:
		print "[-] Stopping Cuckoo Server"
		sys.exit(1)
	except:
		print "[-] Unable to start Cuckoo Server"
		sys.exit(1)
