import hashlib #for MD5/SHA1
import vboxapi
import datetime
import os
from vboxapi.VirtualBox_constants import VirtualBoxReflectionInfo
import subprocess

def forensicSave(ctx, args):
    if (not interpretAndValidate(ctx, args)):
        return 0 #returning other than 0 here exits entire shell; not wanted.
    VMName = args[1]
    destinationDir = os.path.abspath(args[2]) # probably moving to a seperate function
    takeSnapshot(ctx, VMName, destinationDir)
    return 0

def interpretAndValidate(ctx, args):
    if (len(args) < 3 or len(args) > 4):
        print "Usage: forensicSave (vmname|uuid) saveLocation"
        return False
    VMName = args[1]
    machine = nameToMachinePtr(ctx, VMName)
    if machine == None:
        print "Error: Could not find VM named ", VMName, "."
        return False
    return True

# API version agnostic guest lookup
def nameToMachinePtr(ctx, VMName):
    try:
        machine = ctx['vb'].getMachine(VMName)
    except:
        machine = ctx['vb'].findMachine(VMName)
    return machine

# It's a little dirty to not break these out into different functions,
# but the time savings of not having to read in an entire 
# hundred-someodd-gig file twice are enormous.
#
# '20480' is the least common multiple of:
# 160: MD5 block size
# 512: SHA1 block size
# 4096 (or 512, covered by sha1): probable hard drive block size
#
# Also, haskell-style list comprehension return! Whoo!
def multiHash(uri):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(uri,'rb') as file:
        for seg in iter(lambda: file.read(20480), b''):
            md5.update(seg)
            sha1.update(seg)
    file.close()
    return ''.join(["MD5: ", md5.hexdigest(), "\n", "SHA1: ", sha1.hexdigest()])


def takeSnapshot(ctx,VMName, destinationDir):
    print "Taking snapshot... "
    vbm = vboxapi.VirtualBoxManager(None, None)
    vbox = vbm.vbox
    session = vbm.mgr.getSessionObject(vbox)
    machine = nameToMachinePtr(ctx,VMName)
    ctx['vb'].findMachine(VMName).lockMachine(session, vbm.constants.LockType_Shared)
    console = session.console
    print "Temporarily pausing..."
    console.pause()
    print "Paused."
    print "Grabbing a snapshot..."
    date = datetime.datetime.utcnow().isoformat()
    progress = console.takeSnapshot('Forensic Save',"Taken @UTC "+date)
    progress.waitForCompletion(-1)
    print "Snapshot successful."

    print "Dumping memory..."
    memoryURI = destinationDir+'/'+VMName+'-'+date+"-memory.elf"
    memoryError = False
    if (subprocess.call(["vboxmanage", "debugvm", VMName, "dumpguestcore", "--filename", memoryURI ]) != 0):
        print "Memory error encountered."
        memoryError = True
    else:
        print "... done."

# This method will work as soon as VirtualBox accepts patch on bug #10222
#    debugger = console.debugger
#    pagesize=4096
#    npages=(machine.memorySize*1024)/(pagesize/1024)
#    print "Dumping ", npages, " pages of memory (", machine.memorySize*1024, "MB)" 
#    for seek in range(0, npages-1):
#        try:
#            buf=debugger.readPhysicalMemory(seek*pagesize, pagesize)
#        except Exception, e: #MMIO or other reserved area
#            #print "skipping/zeroing for forensic needs reserved/MMIO area @ ", seek*pagesize, "b"
#            buf="\x00"*1024
#        else:
#            raise
        

    print "Reviving (fingers crossed)..."
    console.resume()
    session.unlockMachine()
    print "Done. Machine is now live again, with session unlocked for new commands, and a frozen snapshot state"

    if (not memoryError):
        print "Creating hash set of memory..."
        memoryHash = multiHash(memoryURI)
        print "Memory hashes: ", memoryHash
        file = open(memoryURI+".hash", 'w')
        print >>file, memoryHash
        file.close()

    currentSnapshotID = machine.currentSnapshot.id
    currentParentUUID = currentSnapshotID
    diskUUID = subprocess.check_output(["snap2disk", currentParentUUID]).rstrip()
    print "Parent VM UUID: ", currentParentUUID
    print "Parent VM disk UUID: ", diskUUID

    diskURI = destinationDir+'/'+VMName+'-'+date+"-disk.img"
    diskError = False

    print "Merging disk snapshots and dumping to raw-format disk image..."
    if (subprocess.call(["vboxmanage", "clonehd", diskUUID, "--format", "RAW" , diskURI]) != 0):
        print "Disk error encountered."
        diskError = True
    else:
        print "... done."

    
    if (not diskError):
        print "Creating hash set of disk (may take some time with large disks)..."
        diskHash = multiHash(diskURI)
        print "Disk hashes: ", diskHash
        file = open(diskURI+".hash", 'w')
        print >>file, diskHash
        file.close()


    print "Parent disk location: ", diskUUID
    print "Temporary snapshots located in: ", machine.snapshotFolder
    print "Current snapshot is named: ", machine.currentSnapshot.name, " (", machine.currentSnapshot.description, ")"
    print "Memory dump saved to: ", memoryURI
    print "Disk dump saved to: ", diskURI


#    clone_hd = vbm.vbox.createHardDisk('raw', destinationDir)
#    source_hd = ctx['global'].getArray(machine, 'hardDiskAttachements')[0].hardDisk
#    progress = source_hd.cloneTo(clone_hd,vbc.HardDiskVariant_Standard, None)
#    progress.waitForCompletion(-1)
    print "Done."

commands = {
        'forensicSave': ['Forensically-oriented VM snapshot, forensicSave (vmname|uuid) saveLocation [raw]', forensicSave]
}

def runcmd(async_cmd, *args):
    '''
    Run the bound asynchronous method async_cmd with arguments args.
    Display progress and return once the command has completed.
    If an error occurs print the error and exit the program.
    '''
    try:
        progress = async_cmd(*args)
        while not progress.completed:
            progress.waitForCompletion(30000)   # Update progress every 30 seconds.
            out('%s%% ', progress.percent)
        out('\n')
    except:
        print "failed to run asynchronous command"

def cmdAnyVm(ctx,mach,cmd, args=[],save=False):
    session = ctx['global'].openMachineSession(mach)
    mach = session.machine
    try:
         cmd(ctx, mach, session.console, args)
    except:
        print "couldn't command"
    if save:
         mach.saveSettings()
    ctx['global'].closeMachineSession(session)

