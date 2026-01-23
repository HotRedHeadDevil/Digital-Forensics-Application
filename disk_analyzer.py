# disk_analyzer.py - Main orchestrator for disk image analysis

import pytsk3
import logging
from filesystem_parser import extract_file_metadata, open_filesystem
from yara_scanner import scan_files

logger = logging.getLogger(__name__)

QUICK_MODE_LIMIT = 50


# =======================================================
# HLAVNÍ FUNKCE PRO ANALÝZU OBRAZU DISKU

def analyze_disk_image(image_path, quick_mode=False, yara_rules_path=None):
    """Analyzes disk image and optionally scans files with YARA.
    
    Args:
        image_path: Path to disk image
        quick_mode: Limit scan to first 50 files, skip YARA
        yara_rules_path: Path to YARA rules file (None = use default)
        
    Returns:
        dict: Analysis results or error
    """
    limit = QUICK_MODE_LIMIT if quick_mode else None
    
    if quick_mode:
        logger.info("Quick mode: Skipping YARA scanning.")
    
    result = extract_file_metadata(image_path, quick_mode=quick_mode, limit=limit)
    
    if "error" in result:
        return result
    
    if not quick_mode:
        try:
            img = pytsk3.Img_Info(image_path)
            fs, _ = open_filesystem(img)
            
            if fs:
                result['results'] = scan_files(fs, result['results'], yara_rules_path)
            else:
                logger.warning("Cannot open filesystem for YARA scanning")
                
        except Exception as e:
            logger.error(f"Error during YARA scanning: {e}")
    
    return result