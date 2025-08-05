# nyufile

A FAT32 disk image explorer and manipulation utility in C.

## Contents

- **nyufile.c**: Main CLI for listing directories and extracting files from a FAT32 disk image.
- **nyufile2.c**: Extended CLI with support for writing and creating new files within the disk image.
- **Makefile**: Build targets for compiling `nyufile`, `nyufile2`, and cleaning up artifacts.
- **fat32.disk**: Sample FAT32 disk image for testing and demonstration.
- **newfile.txt**: Example text file used for injection into the disk image.
- **simple.gif**: Example binary file used for demonstration of file extraction and injection.
- **nyufile-autograder/**: Autograder scripts and tests for validating functionality against assignment requirements.
- **.gitignore**: Specifies files and directories to be ignored by Git.

## Building

To compile the utilities, run:

```sh
make all
```

This produces:

- `nyufile`: FAT32 explorer (read-only)
- `nyufile2`: FAT32 image writer (read/write)

## Usage

### Listing files

List all files and directories in the root of the FAT32 image:

```sh
./nyufile fat32.disk
```

### Extracting files

Extract a file from the image to the host filesystem:

```sh
./nyufile fat32.disk simple.gif
```

### Injecting files (write mode)

Write a new file into the FAT32 image:

```sh
./nyufile2 fat32.disk newfile.txt
```

## Cleaning

Remove compiled binaries and object files:

```sh
make clean
```

