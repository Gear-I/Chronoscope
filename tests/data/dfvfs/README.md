# dfVFS test images

Small disk images from the [dfVFS](https://github.com/log2timeline/dfvfs) project's
`test_data` directory (commit `917cefc9426d6ded2687d2b55164ded25b44fcb7`), used to test
Chronoscope's disk image support. They are redistributed under dfVFS's Apache License 2.0;
copyright the dfVFS authors.

| File | Original | Contents |
|---|---|---|
| `ext2.E01` | `test_data/ext2.E01` | EnCase image of an ext2 file system |
| `ntfs.raw.gz` | `test_data/ntfs.raw`, gzipped | NTFS file system, no partition table |
| `fat12.raw.gz` | `test_data/fat12.raw`, gzipped | FAT12 file system, no partition table |
| `mbr.raw.gz` | `test_data/mbr.raw`, gzipped | MBR disk with two ext partitions |

The `.gz` files are gzipped only to keep the repository small; the tests decompress them to a
temporary directory.
