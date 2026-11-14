# disk_analyzer.py - Main orchestrator for disk image analysis

import pytsk3
import logging
from filesystem_parser import extract_file_metadata, open_filesystem
from yara_scanner import scan_files
from system_intelligence import extract_system_intelligence
from analysis_status import AnalysisStatus, report_failed, report_not_run, report_skipped

logger = logging.getLogger(__name__)

ANALYSIS_STAGES_NEEDING_FS = ('system_intelligence', 'command_history', 'yara_scan')


def analyze_disk_image(image_path, quick_mode=False, yara_rules_path=None):
    """Performs basic disk image analysis using pytsk3 and optionally YARA.
    
    Every part of the analysis (filesystem scan, system information, command history,
    YARA) reports into one AnalysisStatus. The result therefore always contains
    'analysis_status', which says for each part whether it completed, was partial,
    failed, could not run or was skipped on purpose, together with the reasons.
    
    Args:
        image_path: Path to disk image
        quick_mode: Skip YARA scanning
        yara_rules_path: Path to YARA rules file (None = use default)
        
    Returns:
        dict: Analysis results or error (both carry 'analysis_status')
    """
    status = AnalysisStatus()

    if quick_mode:
        logger.info("Quick mode: Skipping YARA scanning.")
        report_skipped(status, 'yara_scan', "Skipped on request (--quick)")
    
    result = extract_file_metadata(image_path, quick_mode=quick_mode, status=status)
    
    if "error" in result:
        for stage in ANALYSIS_STAGES_NEEDING_FS:
            if not (quick_mode and stage == 'yara_scan'):
                report_not_run(status, stage, "Filesystem scan failed, nothing to analyse")
        result['analysis_status'] = status.to_dict()
        return result
    
    fs = None
    try:
        img = pytsk3.Img_Info(image_path)
        # No status here: partition problems were already reported by the scan above
        fs, _ = open_filesystem(img)
    except Exception as e:
        logger.error(f"Error opening filesystem: {e}")
        fs = None

    if fs:
        # Extract system intelligence
        system_info = None
        try:
            system_info = extract_system_intelligence(fs, result['results'], status)
            result['system_intelligence'] = system_info
        except Exception as e:
            logger.error(f"Error during system intelligence extraction: {e}")
            report_failed(status, 'system_intelligence',
                          "System intelligence extraction failed: OS details, user profiles and command history are missing",
                          example=f"{type(e).__name__}: {e}")
            report_not_run(status, 'command_history', "System intelligence extraction failed")

        if not quick_mode:
            # Run YARA scanning
            try:
                result['results'], yara_summary = scan_files(fs, result['results'], yara_rules_path, status)
                result['yara_detection'] = yara_summary
            except Exception as e:
                logger.error(f"Error during YARA scanning: {e}")
                report_failed(status, 'yara_scan', "YARA scanning failed",
                              example=f"{type(e).__name__}: {e}")
    else:
        logger.warning("Cannot open filesystem for system/log intelligence or YARA scanning")
        reason = "The filesystem could not be opened a second time for content analysis"
        for stage in ANALYSIS_STAGES_NEEDING_FS:
            if not (quick_mode and stage == 'yara_scan'):
                report_not_run(status, stage, reason)
    
    result['analysis_status'] = status.to_dict()
    return result