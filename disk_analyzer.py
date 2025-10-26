# disk_analyzer.py - OPRAVENÁ VERZE

import pytsk3
import os
import yara

# Konstanty pro cesty a speciální soubory
SKIP_DIRS = ['.', '..']
SYSTEM_FILES = ['$MBR', '$FAT1', '$FAT2', '$OrphanFiles']

# =======================================================
# 1. REKURZIVNÍ FUNKCE PRO PROCHÁZENÍ ADRESÁŘŮ
# =======================================================
def _process_directory(fs, directory, current_path):
    """Rekurzivně prochází adresář a sbírá metadata o souborech."""
    files_data = []

    for entry in directory:
        # Kontrola, zda existuje jméno
        if not entry.info.name:
            continue
            
        file_name = entry.info.name.name.decode('utf-8', 'ignore').strip()
        print(f"Nalezen zaznam: {file_name}")
        
        if file_name in SKIP_DIRS:
            continue

        full_path = os.path.join(current_path, file_name).replace('\\', '/')
        
        try:
            # Získání file_info objektu
            if hasattr(entry.info, 'fs_file'):
                file_info = entry.info.fs_file
            else:
                file_info = entry.info
            
            # Kontrola platnosti
            if not file_info or not hasattr(file_info, 'meta') or file_info.meta.addr == 0:
                print(f"DEBUG: Zaznam {file_name} nemá platný FS uzel, přeskočeno.")
                continue
            
            # OPRAVA: Správná detekce typu - kontrola TSK_FS_META_TYPE
            is_dir = (file_info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
            
            # Filtrování Volume Label (má velikost 0 a je ve FAT)
            is_volume_label = (file_name.endswith('(Volume Label Entry)') or 
                             (file_info.meta.size == 0 and not is_dir and file_name.isupper()))
            
            # Přeskočit Volume Label a systémové soubory
            if is_volume_label or file_name in SYSTEM_FILES:
                print(f"DEBUG: Preskocen systemovy/volume label soubor: {file_name}")
                continue
            
            meta_data = {
                "name": file_name,
                "path": full_path,
                "type": "dir" if is_dir else "file",
                "size": file_info.meta.size,
                "inode": file_info.meta.addr,
                "m_time": file_info.meta.mtime,
                "a_time": file_info.meta.atime,
                "c_time": file_info.meta.ctime,
                "e_time": file_info.meta.crtime 
            }
            
            files_data.append(meta_data)

            # Ověřovací print
            type_str = "DIR" if is_dir else "FILE"
            print(f"DEBUG: Pridano {type_str}: {file_name}, velikost: {file_info.meta.size}")

            # Rekurze pro adresáře
            if is_dir:
                try:
                    sub_directory = fs.open_dir(inode=file_info.meta.addr)
                    files_data.extend(_process_directory(fs, sub_directory, full_path))
                except Exception as e:
                    print(f"Chyba pri rekurzi do adresare {file_name}: {e}")
                    continue 
                
        except Exception as e: 
            print(f"DEBUG: Neocekavana chyba pri zpracovani {file_name}: {e}")
            continue
            
    return files_data


# =======================================================
# 2. HLAVNÍ FUNKCE PRO ANALÝZU OBRAZU DISKU
# =======================================================
def analyze_disk_image(image_path):
    results = []
    
    # 1. Otevření obrazu disku
    try:
        img = pytsk3.Img_Info(image_path)
    except Exception as e:
        return {"error": f"Nelze otevrit obraz: {e}"}

    # 2. Detekce oddílů
    offset = 0
    VS_CLASSES = [
        getattr(pytsk3, 'VS_Info', None),
        getattr(pytsk3, 'Volume_Info', None)
    ]
    
    VolumeInfoClass = next((c for c in VS_CLASSES if c is not None), None)

    if VolumeInfoClass:
        try:
            vol = VolumeInfoClass(img) 
            print("Nalezena tabulka oddílů (MBR/GPT). Hledám první datový oddíl...")
            
            sector_size = getattr(img, 'sector_size', 512)

            for part in vol:
                if part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC and part.start > 0:
                    offset = part.start * sector_size 
                    
                    try:
                        pytsk3.FS_Info(img, offset=offset)
                        print(f"Nalezen platný souborový systém na offsetu: 0x{offset:X}")
                        break
                    except Exception:
                        offset = 0 
                        continue
        
        except Exception as e:
            print(f"Detekce oddílů selhala. Chyba: {e}")

    # 3. Otevření souborového systému
    if offset == 0:
        print("Pokouším se otevřít FS na offsetu 0 (předpoklad: obraz partition).")

    try:
        fs = pytsk3.FS_Info(img, offset=offset)
        
        # Kompilace YARA pravidel
        yara_rules = None
        try:
            yara_rules = yara.compile(filepath='rules/my_rules.yar')
            print("YARA pravidla byla uspesne zkompilovana.")
        except yara.Error as ye:
            print(f"CHYBA YARA: Nepodarilo se zkompilovat pravidla: {ye}")
        except Exception as e:
            print(f"CHYBA: Nelze nacist YARA pravidla: {e}")

        # 4. Rekurzivní procházení
        root_dir = fs.open_dir(path="/")
        results = _process_directory(fs, root_dir, "/")

        # 5. YARA skenování
        if yara_rules:
            print("\nZahajuji YARA skenovani souboru...")
            for item in results:
                # Skenujeme pouze skutečné SOUBORY s velikostí > 0
                if item['type'] == 'file' and item['size'] > 0:
                    try:
                        # Otevření souboru pro čtení
                        fs_file = fs.open_meta(item['inode'])
                        
                        # YARA skenování
                        matches = scan_file_with_yara(yara_rules, fs_file, item['size'])
                        
                        if matches:
                            item['yara_matches'] = matches
                            print(f"YARA MATCH: {item['path']} -> {', '.join(matches)}")
                        
                    except Exception as e:
                        item['yara_error'] = f"Chyba pri YARA skenovani: {str(e)}"
                        print(f"YARA chyba pro {item['path']}: {e}")

    except Exception as e:
        return {"error": f"Chyba pri analyze obrazu: {e}"}
    
    # 6. Spočítání výsledků
    files_scanned = sum(1 for r in results if r['type'] == 'file')
    directories_scanned = sum(1 for r in results if r['type'] == 'dir')
    
    print(f"\n=== VYSLEDKY ===")
    print(f"Soubory: {files_scanned}")
    print(f"Adresare: {directories_scanned}")
    
    return {
        "results": results,
        "files_scanned": files_scanned,
        "directories_scanned": directories_scanned
    }


# =======================================================
# 3. YARA SKENOVACÍ FUNKCE - OPRAVENÁ
# =======================================================
def scan_file_with_yara(yara_rules, fs_file, file_size):
    """Skenuje obsah souboru pomocí YARA pravidel."""
    
    file_content = b''
    try:
        if file_size > 0:
            # Maximální velikost pro skenování (10 MB)
            max_read_size = 10 * 1024 * 1024
            read_size = min(file_size, max_read_size)
            
            # OPRAVA: Používáme přímo file_size parametr místo fs_file.meta.size
            file_content = fs_file.read_random(0, read_size)
        else:
            return []
            
    except Exception as e:
        print(f"Chyba pri cteni souboru pro YARA: {e}")
        return []

    # Provedení skenování
    if file_content:
        try:
            matches = yara_rules.match(data=file_content)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"Chyba pri YARA match: {e}")
            return []
    
    return []