#!/usr/bin/python
__author__ = 'w2k8'
# Version           : 0.6
# Prerequirements   : sleuthkit
# Get the hashes of a filesystem and use the hashes as an ignore set for Forensic tools


import commands
import sys
import multiprocessing
import time
from ctypes import c_int
import os
from multiprocessing import Value, Lock, Process, Manager



replacelist = '0x22,0x27,0x23,0x24,0x25,0x26,0x2c,0x3a,0x3b,0x60,0x7c'
warning = 0
savehashset = 0

counter = Value(c_int)  # defaults to 0
counter_lock = Lock()


def increment():
    with counter_lock:
        counter.value += 1


def start(filepath):
    global nullhash
    global cpucount
    global f
    global tmpfolder
    global counterjob
    nullhash = []

    f = open(filepath.split('\\')[-1].split('/')[-1] + '.hashes.csv', 'w')
    f.write('"MD5","SHA-1","FileName"\n')
    f.close()
    f = open(filepath.split('\\')[-1].split('/')[-1] + '.hashes.csv', 'a')

    cpucount = multiprocessing.cpu_count()

    include_extention, exclude_extention, folder_to_parse, tmpfolder = read_extention_from_file()

    # test is tmpdir exists
    if commands.getoutput('ls {}'.format(tmpfolder)).endswith('No such file or directory'):
        print 'tmp folder not found, creating folder {}'.format(tmpfolder)
        commands.getoutput('mkdir {}'.format(tmpfolder))

    # Test for sleuthkit
    log = commands.getoutput('mmls -V')
    if log[0:14] != 'The Sleuth Kit':
        print 'This script require The Sleuth Kit'
        exit()

    # Test 1
    command = 'file {}'.format(filepath)
    status, log = commands.getstatusoutput(command)
    if log.split(':')[1] != ' EWF/Expert Witness/EnCase image file format':
        print 'Not a EWF file: {}'.format(log.split(':')[1])
        exit()

    # test mmls
    command = 'mmls {}'.format(filepath)
    status, log = commands.getstatusoutput(command)

    # parse log
    start_parse = 0
    filesystemtoparse = []

    for line in log.split('\n'):
        test = line.split()
        if start_parse == 1:
            try:
                testint = int(test[1].split(':')[0]) + int(test[1].split(':')[1])
                offset = test[2]
                filesystem = test[5]
                partitiontype = test[6]
                filesystemtoparse.append((offset, filesystem, partitiontype))
            except ValueError:
                pass

        if 'Slot' in line:
            start_parse = 1

    filejobs = []

    for item in filesystemtoparse:
        # test fls
        command = 'fls {} -o {} -r -p'.format(filepath, item[0])
        log = commands.getoutput(command)

        # Parsing fls log
        print 'Parsing fls log at offset: {}'.format(item[0])
        fsfiles = log.split('\n')
        #count = len(fsfiles)
        for fsitem in fsfiles:
            inode = ''
            fsfilesline = fsitem.split()
            #counter += 1
            # We only hash files, not folders e.a.
            if fsfilesline[0] == 'r/r' or fsfilesline[0] == '-/r':

                for folder in folder_to_parse:
                    folder = folder.split(':')[1]
                    if fsitem.split(':')[1].lower().strip('\t').startswith(folder):

                        # Find known extention and skip them
                        skipthis = 0

                        for ext in exclude_extention:
                            ext = ext.split(':')[1].strip('.')
                            if fsitem[len(fsitem)-len(ext):len(fsitem)].lower() == ext.lower():
                                skipthis = 1

                        inode, filename = isfile(fsitem, fsfilesline)

                        if inode != '' and skipthis == 0:
                            filejobs.append(('icat {} -o {} {}'.format(filepath, item[0], inode), filename, filepath))

                for ext in include_extention:
                    if inode == '':
                        ext = ext.split(':')[1].strip('.')
                        if fsitem[len(fsitem)-len(ext):len(fsitem)].lower() == ext.lower():
                            inode, filename = isfile(fsitem, fsfilesline)
                            filejobs.append(('icat {} -o {} {}'.format(filepath, item[0], inode), filename, filepath))

            if fsfilesline[0] == '-/d':
                pass

    counterjob = len(filejobs)
    count = 0
    testcounter = 0
    print 'Calculating Work'
    print 'Hit [CRTL-z] to abort'
    work = []
    for item, filename, filepath in filejobs:
        work.append((item, filename, filepath))

    p = multiprocessing.Pool(cpucount)
    p.map(worker, work)

    for nullhashitem in nullhash:
        print nullhashitem

def worker(work):
    command, filename, filepath = work
    inode = command.split()[-1]
    #pre_job(inode, command)
    execute_job(command, inode, filename, filepath)
    #cleanup_job(inode)


def pre_job(inode, command):
    command = '{} > {}/{}.tmp'.format(command, tmpfolder, inode)
    log = commands.getoutput(command)


def execute_job(command, inode, filename, filepath):
    increment()

    pct = str(float(1.0 * counter.value / counterjob) * 100)
    pct = '{}.{}'.format(pct.split('.')[0], pct.split('.')[1][0:2])

    commands.getoutput('{} > {}/{}'.format(command, tmpfolder, inode))

    tmp = '{}/{}'.format(tmpfolder, inode)
    resfolder = '{}.res'.format(tmp)

    # create folder and unpack embedded resources.
    commands.getoutput('mkdir {}'.format(resfolder))
    commands.getoutput('wrestool --raw -a -x {} -o {}'.format(tmp, resfolder))

    # unpack zip archives
    # if 'Zip archive' in commands.getoutput('file {}'.format(tmp)):
    # if 'Zip archive' or 'Java archive data' in commands.getoutput('file {}'.format(tmp)):
    if 'archive data' in commands.getoutput('file {}'.format(tmp)):
        try:
            ziplist = zipfile.ZipFile(tmp).namelist()
            for ziplistfile in ziplist:
                archive = zipfile.ZipFile(tmp, 'r')
                data = archive.read(ziplistfile)

                # Replace Windows backslash for underscore
                ziplistfile = ziplistfile.replace('\\', '_').replace('/', '_').strip('"').replace('$', '_')
                fzipfile = open('{}/{}'.format(resfolder, ziplistfile), 'w')
                fzipfile.write(data)
                fzipfile.close()

        except:# BadZipfile:
            # Not a zipfile.
            pass

    for subdir, dirs, files in os.walk(resfolder):
        for dumpedfilename in files:

            dumpedfilename = os.path.join(subdir, dumpedfilename).split(resfolder)[1][1:]

            md5, sha1 = hash_file('{}/{}'.format(resfolder, dumpedfilename))
            filename1 = '{}#{}'.format(filename, dumpedfilename.strip('"'))

            line = '{}% done - "{}","{}","{}"'.format(pct, md5, sha1, filename1)
            print printscreenline(line)
            if md5 != '0' and sha1 != '0':
                writehash(filepath, md5, sha1, filename1)

            # Remove processed file
            commands.getoutput('rm {}/{}'.format(resfolder, dumpedfilename))

    # Remove processed folder
    commands.getoutput('rm -R {}'.format(resfolder))

    md5, sha1 = hash_file('{}/{}'.format(tmpfolder, inode))
    line = '{}% done - "{}","{}","{}"'.format(pct, md5, sha1, filename)
    print printscreenline(line)
    if md5 != '0' and sha1 != '0':
        writehash(filepath, md5, sha1, filename)

    # Remove processed file
    commands.getoutput('rm {}'.format(tmp))


def hash_file(filename):
    sha1 = ''
    md5 = ''
    commandlist = []
    commandlist.append("md5sum '{}'".format(filename))
    commandlist.append("sha1sum '{}'".format(filename))

    for command in commandlist:
        log = commands.getoutput(command)

        # Test for TSK error
        for line in log:
            if not line.startswith('Invalid API argument (tsk_fs_attrlist_get: Null list pointer'):
                if 'md5sum' in command:
                    md5 = log.split()[0]
                if 'sha1sum' in command:
                    sha1 = log.split()[0]
    if len(md5) != 32:
        nullhash.append((md5, sha1, filename, log))
        md5 = '0'

    if len(sha1) != 40:
        nullhash.append((md5, sha1, filename, log))
        sha1 = '0'
    return md5, sha1


def cleanup_job(inode):
    commandlist = []
    commandlist.append('rm {}/{}.tmp'.format(tmpfolder, inode))
    commandlist.append('rm -R {}/{}.tmp.res'.format(tmpfolder, inode))
    for command in commandlist:
        commands.getoutput(command)


def isfile(fsitem, fsfilesline):
    filename = ''
    inode = ''
    if fsfilesline[1] == '*':
        inode = fsfilesline[2].strip(':').split('(')[0]
        filename = fsitem.split(':')[1].strip('\t')
    if fsfilesline[1] != '*':
        inode = fsfilesline[1].strip(':').split('(')[0]
        filename = fsitem.split(':')[1].strip('\t')
    return inode, filename


def printscreenline(printline):
    rows, columns = os.popen('stty size', 'r').read().split()
    if len(printline) > int(columns) - 4:
        printline = '{}...{}'.format(printline[0:int(columns) - 12], printline[(len(printline) - 9):len(printline)])
    return printline


def writehash(filepath, md5, sha, filename):

    line = '"{}","{}","{}"\n'.format(md5, sha, filename)
    # f = global in main function
    try:
        f.write(line)
    except:
        f = open(filepath.split('\\')[-1].split('/')[-1] + '.hashes.csv', 'a')
        f.write(line)

    # Save hashfile for IEF, IEF wants only md5 hashes, no filenames.
    try:
        ief.write('{}\n'.format(md5))
    except:
        ief = open(filepath.split('\\')[-1].split('/')[-1] + '.hashes.ief.csv', 'a')
        ief.write('{}\n'.format(md5))


def read_extention_from_file():
    exclude_extention = []
    include_extention = []
    folder_to_parse = []
    tmpfolder = '/tmp'
    try:
        with open('hash_filesystem_settings.txt') as fs:
            for line in fs:
                if not line.startswith('#') and line.startswith('include:'):
                    include_extention.append(line.strip('\n'))
                if not line.startswith('#') and line.startswith('exlude:'):
                    exclude_extention.append(line.strip('\n'))
                if not line.startswith('#') and line.startswith('folder:'):
                    folder_to_parse.append(line.strip('\n'))
                if not line.startswith('#') and line.startswith('tmpfolder:'):
                    tmpfolder = line.split(':')[1].strip('\n')
    except IOError:
        pass
    return include_extention, exclude_extention, folder_to_parse, tmpfolder


def replacechar(tekst):
    global warning
    test = tekst
    for item in replacelist.split(','):
        tekst = tekst.replace(chr(int(item, 16)), '')
    if test != tekst and warning == 0:
        print 'Illegal char removed'
        warning = 1
    return tekst


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: parse_filesystem.py [filesystem.e01]'
        print ''
        print ''
        exit()
    else:
        start(replacechar(sys.argv[1]))

