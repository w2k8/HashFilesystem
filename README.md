# HashFilesystem
Hash the files in a filesystem to create a hashset for forensic tools.

This script uses an E01 file format as source.

This script uses The Sleuth Kit tools to parse the filesystem and extract the files from the filesystem.
This script hash files in a filesystem and extract files with a zip file header, jar file header and hash the extracted files.
It does not care about file extentions.

Use the genereted hashfile with Forensic tools like EnCase, FTK and IEF.
The generated file contains the MD5 and the SHA1 hash value of the extracted files and the filename from those files.

There is a seperated file genereted with only MD5 hashes For IEF.
