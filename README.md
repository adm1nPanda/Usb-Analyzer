# USB-Analyser Script

This is a python script to automatically submit files on a USB devices to cuckoo sandbox and display its results. 
The script will first fork and start the cuckoo server on one fork and starts a listener on the other fork. Once the USB drive is connected to it grabs information on the USB drive and carves out files from the USB drive, this allows you to grab all files even the deleted files. Once, all files are carved the script submits all files to the cuckoo sadbox and wait until cuckoo is done analysing all the submitted files. Once done, the tool prints out a very brief cuckcoo report and also gives the path to the full report. You can also analyse USB images.

### Options
```
usage: usbfor.py [-h] [-d D [D ...]] [-r] [-c]

A USB Analysis tool

optional arguments:
  -h, --help            show this help message and exit
  -d D [D ...], --dd D [D ...]
                        analyze a dd image of the USB Device
  -r, --report          Generate a report
  -c, --clean           Clean Cuckoo before starting tool
```
### Required python libraries -

1. argparse - ```pip install argparse```
2. pyudev - ```pip install pyudev```
3. pytsk3 - ```pip install pytsk3```

### Install steps

1. Install cuckoo - [Cuckoo Sandbox](https://cuckoosandbox.org/)
   Cuckcoo sandbox will be to be setup properly for the script to run. 
   The install instruction to setup cuckoo properly can be found [here](http://docs.cuckoosandbox.org/en/latest/installation/)
2. Install cuckoo in the same directory as the script
   Tool assumes that you have the cuckoo in the same directory.
3. Run tool with sudo priviledges
   Tool requires sudo to access the USB's /dev partition.

### File hashes
sha1 hashes of all files given below.

1. usbfor.py - 


