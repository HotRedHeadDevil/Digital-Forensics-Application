# yara_scanner.py - YARA scanning module

import yara
import pytsk3
import logging

logger = logging.getLogger(__name__)

DEFAULT_YARA_RULES_PATH = 'rules/my_rules.yar'
MAX_FILE_SCAN_SIZE = 10 * 1024 * 1024  # 10 MB


def compile_yara_rules(rules_path=None):
    """Compiles YARA rules from file.
    
    Args:
        rules_path: Path to YARA rules file (None = use default)
        
    Returns:
        yara.Rules object or None on error
    """
    if rules_path is None:
        rules_path = DEFAULT_YARA_RULES_PATH
    
    try:
        yara_rules = yara.compile(filepath=rules_path)
        logger.info(f"YARA rules successfully compiled from: {rules_path}")
        return yara_rules
    except yara.Error as ye:
        logger.error(f"YARA ERROR: Failed to compile rules: {ye}")
        return None
    except Exception as e:
        logger.error(f"ERROR: Cannot load YARA rules from {rules_path}: {e}")
        return None


def scan_file_content(yara_rules, file_content):
    """Scans file content with YARA rules.
    
    Args:
        yara_rules: Compiled YARA rules
        file_content: Binary file content
        
    Returns:
        list: List of matched rule names
    """
    if not file_content or not yara_rules:
        return []
    
    try:
        matches = yara_rules.match(data=file_content)
        return [match.rule for match in matches]
    except Exception as e:
        logger.warning(f"Error during YARA match: {e}")
        return []


def scan_file_from_fs(yara_rules, fs_file, file_size):
    """Reads file from filesystem and scans with YARA.
    
    Args:
        yara_rules: Compiled YARA rules
        fs_file: PyTSK3 file object
        file_size: File size in bytes
        
    Returns:
        list: List of matched rule names
    """
    file_content = b''
    try:
        if file_size > 0:
            read_size = min(file_size, MAX_FILE_SCAN_SIZE)
            file_content = fs_file.read_random(0, read_size)
        else:
            return []
            
    except Exception as e:
        logger.warning(f"Error reading file for YARA: {e}")
        return []

    return scan_file_content(yara_rules, file_content)


def scan_files(fs, file_list, yara_rules_path=None):
    """Scans list of files with YARA rules.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        yara_rules_path: Path to YARA rules
        
    Returns:
        list: Updated file list with YARA results
    """
    yara_rules = compile_yara_rules(yara_rules_path)
    if not yara_rules:
        logger.warning("YARA rules not compiled, skipping scan")
        return file_list
    
    logger.info("Starting YARA file scanning...")
    scanned_count = 0
    match_count = 0
    
    for item in file_list:
        if item['type'] == 'file' and item['size'] > 0:
            try:
                fs_file = fs.open_meta(item['inode'])
                matches = scan_file_from_fs(yara_rules, fs_file, item['size'])
                
                scanned_count += 1
                
                if matches:
                    item['yara_matches'] = matches
                    match_count += 1
                    logger.info(f"YARA MATCH: {item['path']} -> {', '.join(matches)}")
                
            except Exception as e:
                item['yara_error'] = f"Error during YARA scan: {str(e)}"
                logger.warning(f"YARA error for {item['path']}: {e}")
    
    logger.info(f"YARA scan complete: {scanned_count} files, {match_count} matches")
    return file_list
