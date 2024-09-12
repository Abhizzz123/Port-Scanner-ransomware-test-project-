def detect_ransomware(file_path):
    try:
        # Open the file and read its contents
        with open(file_path, 'r') as file:
            file_content = file.read()

        # Check if 'cryptography' and 'Fernet' are in the file content
        if 'cryptography' in file_content and 'Fernet' in file_content:
            print("Ransomware detected")
        else:
            print("No ransomware detected")
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Ask the user for the file path input
file_path = input("Enter the path to the file you want to check: ")
detect_ransomware(file_path)

