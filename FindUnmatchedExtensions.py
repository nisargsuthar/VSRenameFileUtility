import zipfile
import os
import subprocess
import argparse
from pathlib import Path
from collections import defaultdict
import tempfile
import shutil

def get_extension(mime_type):
    
    mime_type = mime_type.lower()
    if "application/vnd.microsoft.portable-executable" in mime_type:
        return ".exe"
    elif "application/x-dosexec" in mime_type:
        return ".exe"  
    elif "application/x-msdownload" in mime_type:
        return ".dll"
    elif "application/x-elf" in mime_type:
        return ".elf"
    elif "application/pdf" in mime_type:
        return ".pdf"
    elif "text/plain" in mime_type:
        return ".txt"
    elif "application/x-ms-shortcut" in mime_type or "application/octet-stream" in mime_type:
        return ".lnk"  
    elif "application/zip" in mime_type:
        return ".zip"  
    elif "application/x-7z-compressed" in mime_type:
        return ".7z"  
    elif "image/jpeg" in mime_type:
        return ".jpg"
    elif "image/png" in mime_type:
        return ".png"
    elif "application/vnd.ms-excel" in mime_type:
        return ".xls"  
    elif "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in mime_type:
        return ".xlsx"  
    elif "application/vnd.microsoft.word" in mime_type or "application/msword" in mime_type:
        return ".doc"  
    elif "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in mime_type:
        return ".docx"  
    return None  

def determine_filetype(filepath):
    try:
        result = subprocess.run(['file', '--mime-type', '-b', str(filepath)], capture_output=True, text=True)
        mime_type = result.stdout.strip()
        print(f"Detected MIME type for {filepath}: {mime_type}")  MIME types
        return mime_type
    except Exception as e:
        print(f"Error determining file type for {filepath}: {e}")
        return None

def process_zip_files(directory):
    known_types = defaultdict(int)      
    unknown_types = defaultdict(list)   corresponding files
    
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.startswith("VirusShare") and filename.endswith(".zip"):
                zip_path = Path(root) / filename
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_dir_path = Path(temp_dir)
                    try:
                        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir_path, pwd=b'infected')
                            for extracted_file in temp_dir_path.rglob('*'):
                                if extracted_file.is_file():
                                    mime_type = determine_filetype(extracted_file)
                                    extension = get_extension(mime_type)
                                    if extension:
                                        new_file_path = extracted_file.with_suffix(extension)
                                        extracted_file.rename(new_file_path)
                                        print(f"Renamed '{extracted_file}' to '{new_file_path}'")
                                        known_types[mime_type] += 1  type
                                    else:
                                        unknown_types[mime_type].append(str(extracted_file))
                                        print(f"No recognized file extension for '{extracted_file}' (mime type: {mime_type})")
                    except Exception as e:
                        print(f"Failed to process {filename}: {e}")

    print("\nSummary of known MIME types encountered:")
    if known_types:
        for mime, count in known_types.items():
            print(f"{mime}: {count} files")
    else:
        print("No known MIME types encountered.")
    
    print("\nSummary of unrecognized MIME types encountered:")
    if unknown_types:
        for mime, files in unknown_types.items():
            print(f"{mime}: {len(files)} files (e.g., {files[:3]})")  files per MIME type
    else:
        print("All files matched known MIME types.")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Process VirusShare ZIP files recursively, rename extracted files based on type, and report MIME types.')
    parser.add_argument('directory', type=str, help='Directory containing the VirusShare ZIP files.')

    args = parser.parse_args()
    process_zip_files(args.directory)