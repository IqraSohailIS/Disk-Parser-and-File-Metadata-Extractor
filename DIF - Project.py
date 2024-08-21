import os
import hashlib
from PIL import Image
from PIL.ExifTags import TAGS
import fitz

def calculate_md5(file_path):
     hash_md5 = hashlib.md5()
     with open(file_path, "rb") as f:
         for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
     return hash_md5.hexdigest()

def extract_image_metadata(file_path):
    try:
         image = Image.open(file_path)
         info = image._getexif()
         if info:
             for tag, value in info.items():
                 tag_name = TAGS.get(tag, tag)
                 print(f"{tag_name}: {value}")
         else:
            print("No EXIF metadata found.")

    except Exception as e:
        print(f"Error reading image metadata: {e}")

def extract_pdf_metadata(file_path):
     try:
         doc = fitz.open(file_path)
         metadata = doc.metadata
         for key, value in metadata.items():
            print(f"{key}: {value}")

     except Exception as e:
        print(f"Error reading PDF metadata: {e}")

def analyze_directory(directory_path):
     for root, dirs, files in os.walk(directory_path):
         for file in files:
             file_path = os.path.join(root, file)
             print(f"\nAnalyzing file: {file_path}")
             print(f"MD5: {calculate_md5(file_path)}")
             if file.lower().endswith(('jpg', 'jpeg', 'png', 'gif', 'bmp')):
                 print("Image Metadata:")
                 extract_image_metadata(file_path)
             elif file.lower().endswith('pdf'):
                 print("PDF Metadata:")
                 extract_pdf_metadata(file_path)
             else:
                print("No specific metadata extraction available for this file type.")

if __name__ == "__main__":
     directory_to_analyze = input("Enter the directory path to analyze: ")
     analyze_directory(directory_to_analyze)