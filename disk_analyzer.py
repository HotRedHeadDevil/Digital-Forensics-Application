# disk_analyzer.py - Main orchestrator for disk image analysis

import pytsk3
import logging
from filesystem_parser import extract_file_metadata, open_filesystem
from yara_scanner import scan_files
from system_intelligence import extract_system_intelligence
from log_analyzer import extract_log_intelligence

logger = logging.getLogger(__name__)

def analyze_disk_image(image_path, quick_mode=False, yara_rules_path=None):
    """Performs basic disk image analysis using pytsk3 and optionally YARA.
    
    Args:
        image_path: Path to disk image
        quick_mode: Skip YARA scanning
        yara_rules_path: Path to YARA rules file (None = use default)
        
    Returns:
        dict: Analysis results or error
    """
    if quick_mode:
        logger.info("Quick mode: Skipping YARA scanning.")
    
    result = extract_file_metadata(image_path, quick_mode=quick_mode)
    
    if "error" in result:
        return result
    
    try:
        img = pytsk3.Img_Info(image_path)
        fs, _ = open_filesystem(img)
    except Exception as e:
        logger.error(f"Error opening filesystem: {e}")
        fs = None

    if fs:
        # Extract system intelligence
        system_info = None
        try:
            system_info = extract_system_intelligence(fs, result['results'])
            result['system_intelligence'] = system_info
        except Exception as e:
            logger.error(f"Error during system intelligence extraction: {e}")

        # Extract log intelligence (logins, network connections, user/IP frequency)
        if system_info and system_info.get('os_type') in ['linux', 'windows', 'macos']:
            try:
                log_info = extract_log_intelligence(fs, result['results'], system_info['os_type'])
                result['log_intelligence'] = log_info
            except Exception as e:
                logger.error(f"Error during log intelligence extraction: {e}")

        if not quick_mode:
            # Run YARA scanning
            try:
                result['results'], yara_summary = scan_files(fs, result['results'], yara_rules_path)
                result['yara_detection'] = yara_summary
            except Exception as e:
                logger.error(f"Error during YARA scanning: {e}")
    else:
        logger.warning("Cannot open filesystem for system/log intelligence or YARA scanning")
    
    return result