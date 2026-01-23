# validators.py - Input validation

import os
import logging

logger = logging.getLogger(__name__)

SUPPORTED_IMAGE_EXTENSIONS = [
    '.dd', '.raw', '.img',
    '.e01', '.ex01',
    '.aff', '.afd',
    '.001',
]

SUPPORTED_YARA_EXTENSIONS = ['.yar', '.yara']


def validate_file_exists(filepath):
    """Checks if file exists.
    
    Args:
        filepath: Path to file
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not filepath:
        return False, "File path cannot be empty"
    
    if not os.path.exists(filepath):
        return False, f"File does not exist: {filepath}"
    
    if not os.path.isfile(filepath):
        return False, f"Path is not a file: {filepath}"
    
    return True, None


def validate_image_file(filepath):
    """Validates disk image - checks existence and format.
    
    Args:
        filepath: Path to disk image
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    is_valid, error = validate_file_exists(filepath)
    if not is_valid:
        return False, error
    
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return False, f"File is empty: {filepath}"
    
    _, ext = os.path.splitext(filepath.lower())
    if ext not in SUPPORTED_IMAGE_EXTENSIONS:
        logger.warning(
            f"Unknown extension '{ext}'. Supported: {', '.join(SUPPORTED_IMAGE_EXTENSIONS)}"
        )
    
    logger.debug(f"Image validation successful: {filepath} ({file_size / (1024**2):.2f} MB)")
    return True, None


def validate_yara_rules(filepath):
    """Validates YARA rules file.
    
    Args:
        filepath: Path to YARA rules
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    is_valid, error = validate_file_exists(filepath)
    if not is_valid:
        return False, error
    
    _, ext = os.path.splitext(filepath.lower())
    if ext not in SUPPORTED_YARA_EXTENSIONS:
        return False, f"Invalid YARA rules extension: {ext}. Expected {SUPPORTED_YARA_EXTENSIONS}"
    
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return False, f"YARA rules file is empty: {filepath}"
    
    logger.debug(f"YARA rules validation successful: {filepath}")
    return True, None


def validate_output_format(format_type):
    """Validates output format.
    
    Args:
        format_type: Requested output format
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    supported_formats = ['json', 'csv', 'table']
    
    if format_type not in supported_formats:
        return False, f"Unsupported format: {format_type}. Supported: {supported_formats}"
    
    return True, None
