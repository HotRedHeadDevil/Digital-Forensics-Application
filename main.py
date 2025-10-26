import click
import json
import os 
from disk_analyzer import analyze_disk_image # Zajišťuje, že používáš správnou verzi

# --- ZÁKLADNÍ FUNKCE PRO STRUKTUROVANÝ VÝSTUP ---
def print_output(data, format_type='json'):
    """Vypíše data ve strukturovaném formátu (JSON je standard)."""
    if format_type == 'json':
        # Používáme json.dumps pro hezké formátování (indent=4)
        click.echo(json.dumps(data, indent=4))
    # V budoucnu zde můžeš přidat 'csv' nebo 'table' formáty.

@click.group()
def cli():
    """ForensicAutoCLI: Automatizovaný nástroj pro předběžnou analýzu forenzních dat."""
    pass

# --- 1. MODUL: Paměťový dump (memory) ---
@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def memory(filepath):
    """Provede základní analýzu paměťového výpisu (memory dump).
    FILEPATH: Cesta k souboru s paměťovým výpisem.
    """
    click.echo(f"Analyzuji paměťový výpis: {os.path.basename(filepath)}")
    
    # Do tohoto bloku budeme integrovat Volatility / VolPy
    results = {
        "analysis_type": "memory_dump",
        "input_file": filepath,
        "size": f"{os.path.getsize(filepath) / (1024*1024):.2f} MB",
        "status": "in progress",
        "processes_found": 0,
        "note": "Ceka na integraci Volatility a extrakci dat."
    }
    
    print_output(results)

# --- 2. MODUL: Obraz disku (disk) ---
@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def disk(filepath):
    """Provede základní analýzu obrazu disku (RAW, E01 atd.).
    FILEPATH: Cesta k souboru s obrazem disku.
    """
    click.echo(f"Analyzuji obraz disku: {os.path.basename(filepath)}")
    
    # NOVÝ KÓD pro integraci PyTSK3
    
    # TSK analýza
    analysis_data = analyze_disk_image(filepath) # Nyní vrací sjednocený slovník!
    
    # 1. Kontrola chyb
    if "error" in analysis_data:
        # Původní chyba z analyze_disk_image
        summary = {
            "analysis_type": "disk_image",
            "input_file": filepath,
            "total_size_mb": "0.00", # Pro chybu není možné velikost spočítat
            "files_scanned": 0,
            "directories_scanned": 1, # Kvůli původnímu formátu, kde se chyba objevila po 1 dir
            "status": "completed", # Ponecháme completed, ale výsledky jsou v chybě
            "results": [analysis_data]
        }
    
    # 2. Úspěšná analýza
    else:
        # Přímé použití hodnot ze slovníku
        file_list = analysis_data['results']
        total_files = analysis_data['files_scanned']
        total_dirs = analysis_data['directories_scanned']

        # Vypocet celkove velikosti pro prehled
        total_size = sum(f.get('size', 0) for f in file_list if f.get('type') == 'file')
        
        summary = {
            "analysis_type": "disk_image",
            "input_file": filepath,
            "total_size_mb": f"{total_size / (1024*1024):.2f}",
            "files_scanned": total_files,
            "directories_scanned": total_dirs,
            "status": "completed",
            "results": file_list # Vložení skutečných dat (včetně systémových záznamů)
        }
    
    print_output(summary)

# Zde v budoucnu přidáme 'log' modul pro logy a další.

if __name__ == '__main__':
    cli()