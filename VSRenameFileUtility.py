import zipfile
import os
import time
import argparse
import subprocess

def get_extension(mime_type):
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
    elif "text/rtf" in mime_type:
        return ".rtf"
    elif "application/vnd.ms-powerpoint" in mime_type:
        return ".ppt"
    elif "application/vnd.openxmlformats-officedocument.presentationml.presentation" in mime_type:
        return ".pptx"
    elif "application/vnd.android.package-archive" in mime_type:
        return ".apk"
    elif "text/html" in mime_type:
        return ".html"
    elif "application/x-executable" in mime_type:
        return ".out"  
    elif "application/postscript" in mime_type:
        return ".ps"
    elif "application/vnd.ms-outlook" in mime_type:
        return ".msg"
    elif "application/encrypted" in mime_type:
        return ".enc"
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
    
    return ""

def determine_filetype(filepath):
    try:
        result = subprocess.run(['file', '--mime-type', '-b', filepath], capture_output=True, text=True)
        mime_type = result.stdout.strip()  
        return mime_type
    except Exception as e:
        print(f"Error determining file type for {filepath}: {e}")
        return None

def process_zip_files(directory, max_retries=3, request_interval=15):
    for filename in os.listdir(directory):
        
        if filename.startswith("VirusShare") and filename.endswith(".zip"):
            zip_path = os.path.join(directory, filename)
            retries = 0

            while retries < max_retries:
                try:
                    
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(pwd=b'infected')  
                        for extracted_file in zip_ref.namelist():
                            
                            file_path = os.path.join(directory, extracted_file)
                            mime_type = determine_filetype(file_path)

                            
                            extension = get_extension(mime_type)
                            if extension:
                                extracted_filename = f"{extracted_file}{extension}"
                                os.rename(file_path, extracted_filename)
                                print(f"Renamed '{extracted_file}' to '{extracted_filename}'")
                            else:
                                print(f"No recognized file extension for '{extracted_file}' (mime type: {mime_type})")
                    break  

                except Exception as e:
                    print(f"Failed to process {filename}: {e}")
                    retries += 1
                    if retries == max_retries:
                        print(f"Failed to process {filename} after {max_retries} retries.")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Process VirusShare ZIP files and rename extracted files based on type.')
    parser.add_argument('directory', type=str, help='Directory containing the VirusShare ZIP files.')

    args = parser.parse_args()
    process_zip_files(args.directory)
