#ifndef VIDYAGODFS_FUSEOPS_H
#define VIDYAGODFS_FUSEOPS_H

#include <fuse.h>

//Returns the fuse_operations table implementing the overlay/zip/file merged filesystem.
const struct fuse_operations *VidyagodfsOps();

#endif // VIDYAGODFS_FUSEOPS_H
