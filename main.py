import click
import json
import os
import logging
from disk_analyzer import analyze_disk_image
from memory_analyzer import analyze_memory_dump
from validators import validate_image_file, validate_yara_rules, validate_output_format
from output_formatter import format_output

logger = logging.getLogger(__name__)


def print_output(data, format_type='json'):
    """Prints data in structured format (JSON is default)."""
    output = format_output(data, format_type)
    click.echo(output)

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
@click.option('--os-type', type=click.Choice(['windows', 'linux'], case_sensitive=False),
              help='Operating system type (auto-detected if not specified)')
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'table'], case_sensitive=False),
              default='json', help='Output format (default: json)')
def memory(filepath, os_type, output):
    """Performs analysis of memory dump using Volatility 3.
    
    FILEPATH: Path to memory dump file (.raw, .mem, .dmp, .vmem, etc.)
    """
    click.echo(f"Analyzing memory dump: {os.path.basename(filepath)}")
    
    # Analyze memory dump
    analysis_data = analyze_memory_dump(filepath, os_type=os_type.lower() if os_type else None)
    
    if "error" in analysis_data:
        summary = {
            "analysis_type": "memory_dump",
            "input_file": filepath,
            "file_size_mb": analysis_data.get('file_size_mb', 0),
            "status": "error",
            "error": analysis_data["error"]
        }
    else:
        # Build summary with network statistics
        net_stats = analysis_data.get('network_statistics', {})
        
        summary = {
            "analysis_type": "memory_dump",
            "input_file": filepath,
            "file_size_mb": analysis_data.get('file_size_mb', 0),
            "os_type": analysis_data.get('os_type', 'unknown'),
            "hostname": analysis_data.get('hostname'),
            "logged_in_users": analysis_data.get('logged_in_users', []),
            "status": "completed",
            "process_count": len(analysis_data.get('processes', [])),
            "network_connections": len(analysis_data.get('network_connections', [])),
            "network_statistics": net_stats,
            "suspicious_processes": len(analysis_data.get('suspicious_processes', [])),
            "suspicious_items": len(analysis_data.get('suspicious_items', [])),
            "processes": analysis_data.get('processes', []),
            "network": analysis_data.get('network_connections', []),
            "suspicious": analysis_data.get('suspicious_processes', []),
            "suspicious_findings": analysis_data.get('suspicious_items', []),
            "modules": analysis_data.get('loaded_modules', [])
        }
    
    print_output(summary, format_type=output)

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--yara-rules', '-y', type=click.Path(exists=True), 
              help='Path to YARA rules file (default: rules/my_rules.yar)')
@click.option('--quick', is_flag=True, 
              help='Quick mode - limit scan and skip YARA')
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'table'], case_sensitive=False),
              default='json', help='Output format (default: json)')
def disk(filepath, yara_rules, quick, output):
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
        
        # Format size intelligently
        if total_size < 1024:
            size_display = f"{total_size} bytes"
        elif total_size < 1024*1024:
            size_display = f"{total_size/1024:.2f} KB"
        else:
            size_display = f"{total_size/(1024*1024):.2f} MB"
        
        summary = {
            "analysis_type": "disk_image",
            "input_file": filepath,
            "total_size": size_display,
            "files_scanned": total_files,
            "directories_scanned": total_dirs,
            "status": "completed"
        }
        
        # Add system intelligence if available
        if 'system_intelligence' in analysis_data:
            summary['system_intelligence'] = analysis_data['system_intelligence']
        
        # Add log intelligence if available (logins, network connections, user/IP frequency)
        if 'log_intelligence' in analysis_data:
            summary['log_intelligence'] = analysis_data['log_intelligence']
        
        # Add YARA detection summary at the top if available
        if 'yara_detection' in analysis_data:
            summary['yara_detection'] = analysis_data['yara_detection']
        
        # Add detailed results at the end
        summary['results'] = file_list
    
    print_output(summary, format_type=output)

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'table'], case_sensitive=False),
              default='json', help='Output format (default: json)')
def eventlog(filepath, output):
    """Analyzes Windows Event Log files (.evtx, .evt).
    
    FILEPATH: Path to event log file (Security.evtx, System.evtx, etc.)
    """
    click.echo(f"Analyzing event log: {os.path.basename(filepath)}")
    
    # Import event log parsing function
    from log_analyzer import parse_single_event_log
    
    # Parse the event log
    analysis_data = parse_single_event_log(filepath)
    
    if "error" in analysis_data:
        summary = {
            "analysis_type": "event_log",
            "input_file": filepath,
            "status": "error",
            "error": analysis_data["error"]
        }
    else:
        log_type = analysis_data.get('log_type', 'unknown')
        
        summary = {
            "analysis_type": "event_log",
            "input_file": filepath,
            "log_type": log_type,
            "file_size_mb": analysis_data.get('file_size_mb', 0),
            "status": "completed",
            "total_events": analysis_data.get('total_events', 0),
            "events_parsed": analysis_data.get('events_parsed', 0)
        }
        
        # Add security alerts first if available
        if 'security_alerts' in analysis_data:
            security_alerts = analysis_data['security_alerts']
            summary['security_alerts'] = {
                'critical_count': len(security_alerts.get('critical', [])),
                'warning_count': len(security_alerts.get('warnings', [])),
                'info_count': len(security_alerts.get('info', [])),
                'critical': security_alerts.get('critical', []),
                'warnings': security_alerts.get('warnings', []),
                'info': security_alerts.get('info', [])
            }
        
        # Add login events if this is a Security log
        if 'login_events' in analysis_data:
            login_events = analysis_data['login_events']
            summary['login_events'] = {
                'successful_logins': len(login_events.get('successful_logins', [])),
                'failed_logins': len(login_events.get('failed_logins', [])),
                'logoffs': len(login_events.get('logoffs', [])),
                'unique_users': len(login_events.get('user_frequency', {})),
                'unique_ips': len(login_events.get('ip_frequency', {})),
                'top_users': sorted(
                    [{'user': u, 'count': c} for u, c in login_events.get('user_frequency', {}).items()],
                    key=lambda x: x['count'], reverse=True
                )[:10],
                'top_ips': sorted(
                    [{'ip': ip, 'count': c} for ip, c in login_events.get('ip_frequency', {}).items()],
                    key=lambda x: x['count'], reverse=True
                )[:10],
                'details': {
                    'successful_logins': login_events.get('successful_logins', []),
                    'failed_logins': login_events.get('failed_logins', []),
                    'logoffs': login_events.get('logoffs', [])
                }
            }
        
        # Add system events if this is a System log
        if 'system_events' in analysis_data:
            summary['system_events'] = analysis_data['system_events']
    
    print_output(summary, format_type=output)

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'table'], case_sensitive=False),
              default='json', help='Output format (default: json)')
def logs(filepath, output):
    """Analyzes Linux/Unix text log files (auth.log, syslog, secure, etc.).
    
    FILEPATH: Path to log file (/var/log/auth.log, /var/log/syslog, etc.)
    """
    click.echo(f"Analyzing log file: {os.path.basename(filepath)}")
    
    # Import log parsing function
    from log_analyzer import parse_standalone_log
    
    # Parse the log file
    analysis_data = parse_standalone_log(filepath)
    
    if "error" in analysis_data:
        summary = {
            "analysis_type": "text_log",
            "input_file": filepath,
            "status": "error",
            "error": analysis_data["error"]
        }
    else:
        log_type = analysis_data.get('log_type', 'unknown')
        
        summary = {
            "analysis_type": "text_log",
            "input_file": filepath,
            "log_type": log_type,
            "file_size_mb": analysis_data.get('file_size_mb', 0),
            "status": "completed",
            "total_lines": analysis_data.get('total_lines', 0),
            "lines_parsed": analysis_data.get('lines_parsed', 0)
        }
        
        # Add security alerts first if available
        if 'security_alerts' in analysis_data:
            security_alerts = analysis_data['security_alerts']
            summary['security_alerts'] = {
                'critical_count': len(security_alerts.get('critical', [])),
                'warning_count': len(security_alerts.get('warnings', [])),
                'info_count': len(security_alerts.get('info', [])),
                'critical': security_alerts.get('critical', []),
                'warnings': security_alerts.get('warnings', []),
                'info': security_alerts.get('info', [])
            }
        
        # Add login events if this is an auth log
        if 'login_events' in analysis_data:
            login_events = analysis_data['login_events']
            summary['login_events'] = {
                'successful_logins': len(login_events.get('successful_logins', [])),
                'failed_logins': len(login_events.get('failed_logins', [])),
                'ssh_connections': len(login_events.get('ssh_connections', [])),
                'sudo_commands': len(login_events.get('sudo_commands', [])),
                'unique_users': len(login_events.get('user_frequency', {})),
                'unique_ips': len(login_events.get('ip_frequency', {})),
                'top_users': sorted(
                    [{'user': u, 'count': c} for u, c in login_events.get('user_frequency', {}).items()],
                    key=lambda x: x['count'], reverse=True
                )[:10],
                'top_ips': sorted(
                    [{'ip': ip, 'count': c} for ip, c in login_events.get('ip_frequency', {}).items()],
                    key=lambda x: x['count'], reverse=True
                )[:10],
                'details': {
                    'successful_logins': login_events.get('successful_logins', []),
                    'failed_logins': login_events.get('failed_logins', []),
                    'ssh_connections': login_events.get('ssh_connections', []),
                    'sudo_commands': login_events.get('sudo_commands', [])
                }
            }
        
        # Add syslog events if available
        if 'syslog_events' in analysis_data:
            summary['syslog_events'] = analysis_data['syslog_events']
    
    print_output(summary, format_type=output)

if __name__ == '__main__':
    cli()