#!/usr/bin/env python
# test_analyzer.py - Jednoduchý test bez Click

import sys
from disk_analyzer import analyze_disk_image

print("="*60, flush=True)
print("TEST ANALYZERU", flush=True)
print("="*60, flush=True)

if len(sys.argv) < 2:
    print("Usage: python test_analyzer.py <image_path>", flush=True)
    sys.exit(1)

image_path = sys.argv[1]

print(f"\nTestuji soubor: {image_path}", flush=True)
print("Spoustim analyzu v QUICK MODE...\n", flush=True)

try:
    results = analyze_disk_image(image_path, quick_mode=True)
    
    print("\n" + "="*60, flush=True)
    print("VYSLEDKY:", flush=True)
    print("="*60, flush=True)
    
    if "error" in results:
        print(f"CHYBA: {results['error']}", flush=True)
    else:
        print(f"Soubory: {results.get('files_scanned', 0)}", flush=True)
        print(f"Adresare: {results.get('directories_scanned', 0)}", flush=True)
        print(f"Status: {results.get('status', 'unknown')}", flush=True)
        
        print(f"\nNalezene soubory:", flush=True)
        for item in results.get('results', [])[:10]:  # Prvnich 10
            print(f"  - {item['path']} ({item['size']} bytes)", flush=True)
    
    print("\n✅ Test dokoncen!", flush=True)
    
except Exception as e:
    print(f"\n❌ CHYBA: {e}", flush=True)
    import traceback
    traceback.print_exc()