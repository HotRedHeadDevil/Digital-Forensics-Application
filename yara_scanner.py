# yara_scanner.py - YARA scanning module

import pytsk3
import logging

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

DEFAULT_YARA_RULES_PATH = 'rules/my_rules.yar'
MAX_FILE_SCAN_SIZE = 10 * 1024 * 1024  # 10 MB


def compile_yara_rules(rules_path=None):
    """Compiles YARA rules from file.
    
    Args:
        rules_path: Path to YARA rules file (None = use default)
        
    Returns:
        yara.Rules object or None on error
    """
    if not YARA_AVAILABLE:
        logger.error("yara-python not installed. Run: pip install yara-python. Skipping YARA scanning.")
        return None

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


def _read_file_content(fs_file, file_size):
    """Read up to MAX_FILE_SCAN_SIZE bytes of a file (b'' on error)."""
    try:
        if file_size > 0:
            return fs_file.read_random(0, min(file_size, MAX_FILE_SCAN_SIZE))
    except Exception as e:
        logger.warning(f"Error reading file for YARA: {e}")
    return b''


def scan_file_content(yara_rules, file_content):
    """Scans file content with YARA rules.

    Args:
        yara_rules: Compiled YARA rules
        file_content: Binary file content

    Returns:
        list: List of yara Match objects
    """
    if not file_content or not yara_rules:
        return []
    try:
        return list(yara_rules.match(data=file_content))
    except Exception as e:
        logger.warning(f"Error during YARA match: {e}")
        return []


# Only folders that normally hold user data are scanned. System folders (/etc, /usr,
# /var/lib, \\Windows, ...) are huge and match generic rules (IP, URL, e-mail) thousands
# of times without telling anything about the user. Files directly in the root are scanned too.
SCAN_PREFIXES = (
    '/home/', '/root/', '/tmp/', '/var/tmp/', '/dev/shm/', '/var/www/', '/srv/', '/opt/', '/mnt/', '/media/',
    '/users/', '/temp/', '/windows/temp/',
)


def _is_system_path(path):
    """True for files outside the user-data folders (these are not scanned)."""
    lowered = path.lower()
    if lowered.count('/') <= 1:      # file directly in the root
        return False
    return not lowered.startswith(SCAN_PREFIXES)


_SEVERITY_ORDER = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}

# Shell history files are analysed by the command rules; YARA would only repeat that
HISTORY_FILENAMES = {'.bash_history', '.zsh_history', '.history', '.sh_history', 'consolehost_history.txt'}


def scan_files(fs, file_list, yara_rules_path=None):
    """Scans list of files with YARA rules.

    Returns one entry per matching file with every rule that matched.

    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        yara_rules_path: Path to YARA rules

    Returns:
        tuple: (Updated file list with YARA results, YARA summary dict)
    """
    yara_rules = compile_yara_rules(yara_rules_path)
    if not yara_rules:
        logger.warning("YARA rules not compiled, skipping scan")
        return file_list, None

    logger.info("Starting YARA file scanning...")
    scanned_count = 0
    skipped_system = 0
    detections = []

    for item in file_list:
        if item['type'] == 'file' and item['size'] > 0 and _is_system_path(item['path']):
            skipped_system += 1
            continue
        if item['type'] == 'file' and item['size'] > 0:
            try:
                fs_file = fs.open_meta(item['inode'])
                content = _read_file_content(fs_file, item['size'])
                matches = scan_file_content(yara_rules, content)
                scanned_count += 1

                rules = []
                for match in matches:
                    meta = match.meta or {}
                    rules.append({
                        'rule': match.rule,
                        'severity': str(meta.get('severity', 'medium')).lower(),
                        'description': meta.get('description', ''),
                    })

                if rules and item['name'].lower() in HISTORY_FILENAMES:
                    rules = []

                if rules:
                    rules.sort(key=lambda r: -_SEVERITY_ORDER.get(r['severity'], 0))
                    item['yara_matches'] = [r['rule'] for r in rules]
                    detections.append({
                        'file': item['path'],
                        'size': item['size'],
                        'severity': rules[0]['severity'],
                        'rules': rules,
                    })
                    logger.info(f"YARA MATCH: {item['path']} -> {', '.join(item['yara_matches'])}")

            except Exception as e:
                item['yara_error'] = f"Error during YARA scan: {str(e)}"
                logger.warning(f"YARA error for {item['path']}: {e}")

    detections.sort(key=lambda d: (-_SEVERITY_ORDER.get(d['severity'], 0), d['file']))
    logger.info(f"YARA scan complete: {scanned_count} files, {len(detections)} with detections")

    summary = {
        'total_files_scanned': scanned_count,
        'files_skipped_system_folders': skipped_system,
        'files_with_matches': len(detections),
        'total_detections': len(detections),
        'detections': detections,
    }

    return file_list, summary