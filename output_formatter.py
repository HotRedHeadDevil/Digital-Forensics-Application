# output_formatter.py - Output formatting for various formats

import json
import csv
import io
from datetime import datetime


def format_json(data):
    """Format data as JSON string.
    
    Args:
        data: Dictionary to format
        
    Returns:
        str: Formatted JSON string
    """
    return json.dumps(data, indent=4)


def format_csv(data):
    """Format data as CSV string.
    
    Args:
        data: Dictionary containing analysis results
        
    Returns:
        str: CSV formatted string
    """
    output = io.StringIO()
    
    if 'results' not in data or not data['results']:
        return "No results to export"
    
    # Extract file/directory entries
    results = data['results']
    
    # Define CSV columns
    fieldnames = ['name', 'path', 'type', 'size', 'inode', 'm_time', 'a_time', 'c_time', 'e_time', 'yara_matches']
    
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    
    for item in results:
        row = item.copy()
        # Convert yara_matches list to comma-separated string
        if 'yara_matches' in row:
            row['yara_matches'] = ', '.join(row['yara_matches'])
        writer.writerow(row)
    
    return output.getvalue()


def format_table(data):
    """Format data as ASCII table.
    
    Args:
        data: Dictionary containing analysis results
        
    Returns:
        str: ASCII table formatted string
    """
    output = []
    
    # Print summary section
    output.append("=" * 110)
    output.append("FORENSIC ANALYSIS SUMMARY")
    output.append("=" * 110)
    output.append(f"Analysis Type: {data.get('analysis_type', 'N/A')}")
    output.append(f"Input File: {data.get('input_file', 'N/A')}")
    output.append(f"Status: {data.get('status', 'N/A')}")
    output.append(f"Total Size: {data.get('total_size', '0 bytes')}")
    output.append(f"Files: {data.get('files_scanned', 0)}")
    output.append(f"Directories: {data.get('directories_scanned', 0)}")
    output.append("")
    
    # Print system intelligence if available
    if 'system_intelligence' in data:
        sys_info = data['system_intelligence']
        output.append("-" * 110)
        output.append("SYSTEM INTELLIGENCE")
        output.append("-" * 110)
        output.append(f"OS Type: {sys_info.get('os_type', 'Unknown').upper()}")
        
        if sys_info.get('hostname'):
            output.append(f"Hostname: {sys_info['hostname']}")
        
        if sys_info.get('os_info'):
            os_details = sys_info['os_info']
            if os_details.get('name'):
                output.append(f"OS Name: {os_details['name']}")
            if os_details.get('version'):
                output.append(f"OS Version: {os_details['version']}")
        
        if sys_info.get('user_profiles'):
            output.append(f"User Profiles: {len(sys_info['user_profiles'])}")
            for user in sys_info['user_profiles']:
                output.append(f"  • {user}")
        else:
            output.append("User Profiles: None detected")
        
        output.append("")
    
    # Print YARA detection summary if available
    if 'yara_detection' in data:
        yara = data['yara_detection']
        output.append("-" * 110)
        output.append("YARA DETECTION SUMMARY")
        output.append("-" * 110)
        output.append(f"Files Scanned: {yara.get('total_files_scanned', 0)}")
        output.append(f"Files with Matches: {yara.get('files_with_matches', 0)}")
        output.append(f"Total Detections: {yara.get('total_detections', 0)}")
        output.append("")
        
        if yara.get('detections'):
            output.append("Detections:")
            for detection in yara['detections']:
                output.append(f"  • {detection['file']}")
                output.append(f"    Rule: {detection['rule']}")
                output.append(f"    Size: {detection['size']} bytes")
        output.append("")
    
    # Print results table
    if 'results' in data and data['results']:
        output.append("-" * 110)
        output.append("FILES AND DIRECTORIES")
        output.append("-" * 110)
        
        # Table header with fixed column widths
        header = f"{'Type':<8} {'Name':<40} {'Size':<12} {'YARA Matches':<35}"
        output.append(header)
        output.append("-" * 110)
        
        for item in data['results']:
            item_type = item.get('type', 'N/A')
            name = item.get('name', 'N/A')
            
            # Truncate long names with ellipsis
            if len(name) > 39:
                name = name[:36] + '...'
            
            # Format size better
            if item.get('type') == 'file':
                size_bytes = item.get('size', 0)
                if size_bytes < 1024:
                    size = f"{size_bytes} B"
                elif size_bytes < 1024*1024:
                    size = f"{size_bytes/1024:.1f} KB"
                else:
                    size = f"{size_bytes/(1024*1024):.2f} MB"
            else:
                size = '-'
            
            # Format YARA matches with fixed width
            if 'yara_matches' in item and item['yara_matches']:
                yara = ', '.join(item['yara_matches'])
                # Truncate if too long
                if len(yara) > 34:
                    yara = yara[:31] + '...'
            else:
                yara = '-'
            
            row = f"{item_type:<8} {name:<40} {size:<12} {yara:<35}"
            output.append(row)
    
    output.append("=" * 110)
    
    return '\n'.join(output)


def format_output(data, format_type='json'):
    """Format data according to specified format.
    
    Args:
        data: Dictionary to format
        format_type: Output format ('json', 'csv', 'table')
        
    Returns:
        str: Formatted output string
    """
    formatters = {
        'json': format_json,
        'csv': format_csv,
        'table': format_table
    }
    
    formatter = formatters.get(format_type, format_json)
    return formatter(data)
