#ifndef VIDYAGODFS_FUSEOPS_H
#define VIDYAGODFS_FUSEOPS_H

#include <fuse.h>

//How long (seconds) the kernel keeps a lookup, a file's attributes and a miss without asking (op_init).
constexpr double kEntryTimeout = 10.0, kAttrTimeout = 10.0, kNegativeTimeout = 5.0;

//Returns the fuse_operations table implementing the overlay/zip/file merged filesystem.
const struct fuse_operations *VidyagodfsOps();

#endif // VIDYAGODFS_FUSEOPS_H
