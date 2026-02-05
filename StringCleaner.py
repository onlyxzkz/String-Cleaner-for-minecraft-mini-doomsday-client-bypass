import ctypes
import pymem
import os
import shutil


PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', ctypes.c_ulong),
        ('RegionSize', ctypes.c_size_t),
        ('State', ctypes.c_ulong),
        ('Protect', ctypes.c_ulong),
        ('Type', ctypes.c_ulong),
    ]

def hide_string_full_scan(process_name, target_string):
    try:
        pm = pymem.Pymem(process_name)
        print(f"[INFO] Proces found: {process_name}")

        target_bytes = target_string.encode('utf-8')
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        kernel32 = ctypes.windll.kernel32
        found_any = False

        
        while address < 0x7FFFFFFFFFFF:
            if kernel32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                       ctypes.sizeof(mbi)):
                
                if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
                    try:
                        data = pm.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                        offset = 0
                        while True:
                            offset = data.find(target_bytes, offset)
                            if offset == -1:
                                break
                            
                            addr = mbi.BaseAddress + offset
                            print(f"[OK] Found '{target_string}' at {hex(addr)}")
                            
                            pm.write_bytes(addr, b'\x00' * len(target_bytes), len(target_bytes))
                            found_any = True
                            offset += len(target_bytes) 
                    except Exception:
                        pass
                address += mbi.RegionSize
            else:
                break

        if not found_any:
            print(f"[!] String not found '{target_string}' in memory.")
        else:
            print(f"[DONE] All occurrences of '{target_string}' have been overwritten.")

    except Exception as e:
        print(f"[ERROR] {str(e)}")

def cleanup_jre_usage_folder():
    folder_path = r"C:\ProgramData\Oracle\Java\.oracle_jre_usage"
    try:
        if os.path.exists(folder_path):
            print(f"\n[INFO] Cleaning folder: {folder_path}")
            shutil.rmtree(folder_path)
            print("[DONE] Folder has been deleted.")
        else:
            print(f"\n[INFO] Folder {folder_path} does not exist (already cleaned).")
    except Exception as e:
        print(f"[ERROR] Error while cleaning folder: {str(e)}")

if __name__ == "__main__":
    print("=== String cleaner for (javaw.exe) ===")
    print("Enter the string to be removed and press Enter.")
    print("Type 'exit' to finish and proceed to folder cleanup.")
    
    while True:
        s = input("\nEnter string to remove: ").strip()
        
        if s.lower() == 'exit':
            break
            
        if not s:
            print("[!] Please enter correct string.")
            continue

        print(f"--- Starting scan for: {s} ---")
        hide_string_full_scan("javaw.exe", s)

    
    cleanup_jre_usage_folder()
    print("\n[END] Program has finished running.")