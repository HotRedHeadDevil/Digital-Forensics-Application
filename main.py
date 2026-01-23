import click
import json
import os
import logging
from disk_analyzer import analyze_disk_image
from validators import validate_image_file, validate_yara_rules

logger = logging.getLogger(__name__)


def print_output(data, format_type='json'):
    """Prints data in structured format (JSON is default)."""
    if format_type == 'json':
        click.echo(json.dumps(data, indent=4))

@click.group()
@click.option('--verbose', '-v', count=True, 
              help='Increase output verbosity (-v: INFO, -vv: DEBUG)')
def cli(verbose):
    """ForensicAutoCLI: Automated tool for preliminary forensic data analysis."""
    if verbose == 0:
        log_level = logging.WARNING
    elif verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
    
    logging.basicConfig(
        level=log_level,
        format='%(levelname)s: %(message)s',
        force=True
    )
    
    logger.debug(f"Logging level set to: {logging.getLevelName(log_level)}")

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def memory(filepath):
    """Performs basic analysis of memory dump.
    
    FILEPATH: Path to memory dump file.
    """
    click.echo(f"Analyzing memory dump: {os.path.basename(filepath)}")
    
    results = {
        "analysis_type": "memory_dump",
        "input_file": filepath,
        "size": f"{os.path.getsize(filepath) / (1024*1024):.2f} MB",
        "status": "not_implemented",
        "note": "Awaiting Volatility integration."
    }
    
    print_output(results)

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--yara-rules', '-y', type=click.Path(exists=True), 
              help='Path to YARA rules file (default: rules/my_rules.yar)')
@click.option('--quick', is_flag=True, 
              help='Quick mode - limit scan and skip YARA')
def disk(filepath, yara_rules, quick):
    """Performs basic analysis of disk image (RAW, E01, etc.).
    
    FILEPATH: Path to disk image file.
    """
    is_valid, error = validate_image_file(filepath)
    if not is_valid:
        click.echo(json.dumps({"error": error}, indent=4), err=True)
        return
    
    if yara_rules:
        is_valid, error = validate_yara_rules(yara_rules)
        if not is_valid:
            click.echo(json.dumps({"error": error}, indent=4), err=True)
            return
    
    click.echo(f"Analyzing disk image: {os.path.basename(filepath)}")
    
    analysis_data = analyze_disk_image(filepath, quick_mode=quick, yara_rules_path=yara_rules)
    
    if "error" in analysis_data:
        summary = {
            "analysis_type": "disk_image",
            "input_file": filepath,
            "total_size_mb": "0.00",
            "files_scanned": 0,
            "directories_scanned": 0,
            "status": "error",
            "results": [analysis_data]
        }
    else:
        file_list = analysis_data['results']
        total_files = analysis_data['files_scanned']
        total_dirs = analysis_data['directories_scanned']
        total_size = sum(f.get('size', 0) for f in file_list if f.get('type') == 'file')
        
        summary = {
            "analysis_type": "disk_image",
            "input_file": filepath,
            "total_size_mb": f"{total_size / (1024*1024):.2f}",
            "files_scanned": total_files,
            "directories_scanned": total_dirs,
            "status": "completed",
            "results": file_list
        }
    
    print_output(summary)

if __name__ == '__main__':
    cli()