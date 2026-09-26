# filesystem_parser.py - Filesystem parsing module

import pytsk3
import os
import logging

logger = logging.getLogger(__name__)

SKIP_DIRS = ['.', '..']
SYSTEM_FILES = ['$MBR', '$FAT1', '$FAT2', '$OrphanFiles']
DEFAULT_SECTOR_SIZE = 512
MAX_RECURSION_DEPTH = 100  # safety limit against directory cycles / corrupted filesystems

_FAT_FS_TYPE_NAMES = ['TSK_FS_TYPE_FAT12', 'TSK_FS_TYPE_FAT16', 'TSK_FS_TYPE_FAT32',
                      'TSK_FS_TYPE_FAT_DETECT', 'TSK_FS_TYPE_EXFAT']
FAT_FS_TYPES = {getattr(pytsk3, name) for name in _FAT_FS_TYPE_NAMES if hasattr(pytsk3, name)}

_partition_warning_shown = False


def _is_fat_like_filesystem(fs):
    """Whether fs is a FAT/exFAT filesystem.

    Args:
        fs: PyTSK3 FS_Info object

    Returns:
        bool: True if fs is a FAT-family filesystem
    """
    try:
        return fs.info.ftype in FAT_FS_TYPES
    except Exception:
        return False


def open_filesystem(img):
    """Detects partition offset and opens filesystem.
    
    Args:
        img: PyTSK3 Img_Info object
        
    Returns:
        tuple: (pytsk3.FS_Info, offset) or (None, None) on error
    """
    global _partition_warning_shown
    
    offset = 0
    VS_CLASSES = [
        getattr(pytsk3, 'VS_Info', None),
        getattr(pytsk3, 'Volume_Info', None)
    ]
    
    VolumeInfoClass = next((c for c in VS_CLASSES if c is not None), None)

    if VolumeInfoClass:
        try:
            vol = VolumeInfoClass(img) 
            logger.info("Found partition table (MBR/GPT). Looking for first data partition...")
            
            sector_size = getattr(img, 'sector_size', DEFAULT_SECTOR_SIZE)

            for part in vol:
                if part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC and part.start > 0:
                    offset = part.start * sector_size 
                    
                    try:
                        pytsk3.FS_Info(img, offset=offset)
                        logger.info(f"Found valid filesystem at offset: 0x{offset:X}")
                        break
                    except Exception:
                        offset = 0 
                        continue
        
        except Exception as e:
            # Only show warning once per run
            if not _partition_warning_shown:
                logger.warning(f"No partition table found - analyzing as raw partition image (this is normal for .dd files)")
                logger.debug(f"Partition detection details: {e}")
                _partition_warning_shown = True

    if offset == 0:
        logger.info("Attempting to open FS at offset 0 (assuming partition image).")

    try:
        fs = pytsk3.FS_Info(img, offset=offset)
        return fs, offset
    except Exception as e:
        logger.error(f"Cannot open filesystem: {e}")
        return None, None


def scan_directory(fs, directory, current_path, visited_inodes=None, depth=0, is_fat_fs=None):
    """Recursively scans directory and collects file metadata.
    
    Args:
        fs: PyTSK3 FS_Info object
        directory: Current directory to scan
        current_path: Path to current directory
        visited_inodes: Set of directory inode addresses already scanned in
            this run
        depth: Current recursion depth, used to enforce MAX_RECURSION_DEPTH
        is_fat_fs: Whether fs is a FAT/exFAT filesystem
        
    Returns:
        list: List of dictionaries with file metadata
    """
    if visited_inodes is None:
        visited_inodes = set()

    if is_fat_fs is None:
        is_fat_fs = _is_fat_like_filesystem(fs)

    if depth > MAX_RECURSION_DEPTH:
        logger.warning(f"Max recursion depth ({MAX_RECURSION_DEPTH}) reached at '{current_path}', stopping recursion here (possible directory cycle or corrupted filesystem).")
        return []

    files_data = []

    for entry in directory:
        if not entry.info.name:
            continue
            
        file_name = entry.info.name.name.decode('utf-8', 'ignore').strip()
        logger.debug(f"Found entry: {file_name}")
        
        if file_name in SKIP_DIRS:
            continue

        full_path = os.path.join(current_path, file_name).replace('\\', '/')
        
        try:
            if hasattr(entry.info, 'fs_file'):
                file_info = entry.info.fs_file
            else:
                file_info = entry.info
            
            if not file_info or not hasattr(file_info, 'meta') or file_info.meta.addr == 0:
                logger.debug(f"Entry {file_name} has no valid FS node, skipped.")
                continue
            
            is_dir = (file_info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
            
            is_volume_label = (file_name.endswith('(Volume Label Entry)') or 
                             (is_fat_fs and file_info.meta.size == 0 and not is_dir and file_name.isupper()))
            
            if is_volume_label or file_name in SYSTEM_FILES:
                logger.debug(f"Skipped system/volume label file: {file_name}")
                continue
            
            meta_data = {
                "name": file_name,
                "path": full_path,
                "type": "dir" if is_dir else "file",
                "size": file_info.meta.size,
                "inode": file_info.meta.addr,
                "m_time": file_info.meta.mtime,
                "a_time": file_info.meta.atime,
                "c_time": file_info.meta.ctime,
                "e_time": file_info.meta.crtime 
            }
            
            files_data.append(meta_data)

            type_str = "DIR" if is_dir else "FILE"
            logger.debug(f"Added {type_str}: {file_name}, size: {file_info.meta.size}")

            if is_dir:
                if file_info.meta.addr in visited_inodes:
                    logger.warning(f"Directory cycle detected: '{full_path}' (inode {file_info.meta.addr}) was already scanned, skipping to avoid infinite recursion.")
                    continue

                visited_inodes.add(file_info.meta.addr)
                try:
                    sub_directory = fs.open_dir(inode=file_info.meta.addr)
                    files_data.extend(scan_directory(fs, sub_directory, full_path, visited_inodes, depth + 1, is_fat_fs))
                except Exception as e:
                    logger.warning(f"Error recursing into directory {file_name}: {e}")
                    continue 
                
        except Exception as e: 
            logger.debug(f"Unexpected error processing {file_name}: {e}")
            continue
            
    return files_data


def extract_file_metadata(image_path, quick_mode=False, limit=None):
    """Extracts metadata of all files from disk image.
    
    Args:
        image_path: Path to disk image
        quick_mode: Kept for API compatibility; does not limit results
        limit: Maximum number of files to return (None = no limit)
        
    Returns:
        dict: Results dictionary or error
    """
    try:
        img = pytsk3.Img_Info(image_path)
    except Exception as e:
        return {"error": f"Cannot open image: {e}"}

    fs, offset = open_filesystem(img)
    if fs is None:
        return {"error": "Cannot open filesystem"}

    try:
        root_dir = fs.open_dir(path="/")
        results = scan_directory(fs, root_dir, "/")
        
        if limit and len(results) > limit:
            logger.info(f"Limiting results to first {limit} of {len(results)} items.")
            results = results[:limit]
            
    except Exception as e:
        return {"error": f"Error scanning files: {e}"}
    
    files_scanned = sum(1 for r in results if r['type'] == 'file')
    directories_scanned = sum(1 for r in results if r['type'] == 'dir')
    
    logger.info(f"=== RESULTS ===")
    logger.info(f"Files: {files_scanned}")
    logger.info(f"Directories: {directories_scanned}")
    
    return {
        "results": results,
        "files_scanned": files_scanned,
        "directories_scanned": directories_scanned,
        "filesystem_offset": offset
    }
