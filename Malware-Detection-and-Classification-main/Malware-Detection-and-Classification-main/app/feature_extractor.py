import pefile
import os

def extract_features(file_path):
    features = []
    try:
        pe = pefile.PE(file_path)

        # Number of sections in the file
        features.append(len(pe.sections))

        # Entry point of the program
        features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Size of headers
        features.append(pe.OPTIONAL_HEADER.SizeOfHeaders)

        # Machine type
        features.append(pe.FILE_HEADER.Machine)

        # Total file size in bytes
        features.append(os.path.getsize(file_path))

        # Average entropy of all sections (how random)
        entropies = [section.get_entropy() for section in pe.sections]
        avg_entropy = sum(entropies) / len(entropies)
        features.append(avg_entropy)

    except Exception as e:
        print("⚠️ Could not extract features:", e)
        features = [0, 0, 0, 0, 0, 0]  # fallback values

    return features
