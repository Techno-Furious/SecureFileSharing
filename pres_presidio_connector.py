"""
Presidio analyzer engine integration module for sensitive data detection.
Configures custom recognizers for various entity types including financial data, names, and tokens.
Provides text extraction utilities for multiple file formats and sensitivity analysis functions.
Generates synthetic test data for pattern recognition training and validation purposes.
"""

from presidio_analyzer import AnalyzerEngine, PatternRecognizer,Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import json
from pprint import pprint
import os
from docx import Document
import PyPDF2
import json
import random
from faker import Faker
import os
from pres_helper_constants import *

faker = Faker()
random.seed(999)

# Synthetic data generation configuration
output_folder = "fake_data"
os.makedirs(output_folder, exist_ok=True)
NUM_RECORDS = 2000

def generate_and_save(entity_name, generator_func):
    """Generate and save synthetic data for entity recognition training."""
    random.seed(random.randint(1,9999999999999999))
    data_list = [generator_func() for _ in range(NUM_RECORDS)]
    file_path = os.path.join(output_folder, f"{entity_name}_data.jsonl")
    with open(file_path, "a") as f:
        for item in data_list:
            f.write(json.dumps(item) + "\n")
    print(f"Saved {NUM_RECORDS} records to {file_path}")

# Synthetic data generators for various entity types
def generate_iban():
    return {"iban": faker.iban()}

def generate_swift():
    length = random.choice([8, 11])
    return {"swift": faker.swift(length=length)}

def generate_salary():
    # Major currency symbols for salary recognition
    major_symbols = ['$', '₹', '£', '¥','Rs ','HKD ']
    currency_symbol = random.choice(major_symbols)
    salary_value = f"{currency_symbol}{random.randint(1000, 10000)}.{random.randint(0, 99):02d}"
    return {"salary": salary_value}

def generate_first_name():
    return {"first_name": random.choice([
        faker.first_name(),
        faker.first_name_female(),
        faker.first_name_male()
    ])}

def generate_last_name():
    return {"last_name": random.choice([
        faker.last_name(),
        faker.last_name_female(),
        faker.last_name_male()
    ])}

def generate_jwt():
    """Generate synthetic JWT tokens for recognition training."""
    header = '{"alg":"HS256","typ":"JWT"}'
    payload = {
        "sub": faker.uuid4(),
        "name": faker.name(),
        "iat": random.randint(1000000000, 2000000000)
    }
    import base64
    header_b64 = base64.urlsafe_b64encode(header.encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature_b64 = faker.sha256(raw_output=False)[:32]
    jwt_value = f"{header_b64}.{payload_b64}.{signature_b64}"
    return {"jwt": jwt_value}

def get_records(entity_name):
    """Load synthetic data records from file for recognizer training."""
    file_path = os.path.join(output_folder, f"{entity_name}_data.jsonl")
    records = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                data = json.loads(line)
                records.append(list(data.values())[0])
    except FileNotFoundError:
        print(f"Warning: File {file_path} not found. Run this script directly to generate data.")
        records = []
    return records

# Data generation entry point
if __name__ == "__main__":
    # Generate synthetic data for all entity types
    generate_and_save("iban", generate_iban)
    generate_and_save("swift", generate_swift)
    generate_and_save("salary", generate_salary)
    generate_and_save("first_name", generate_first_name)
    generate_and_save("last_name", generate_last_name)
    generate_and_save("jwt", generate_jwt)
    
    # Example usage
    salary_data = get_records("salary")
    print(salary_data[:5])

# Initialize Presidio analyzer engine
analyzer = AnalyzerEngine()

# Custom recognizer configuration
first_name_list = get_records("first_name")
first_name_recognizer = PatternRecognizer(
    supported_entity="FIRST_NAME",
    deny_list=first_name_list,
    context=["name", "first name", "given name"]
)
analyzer.registry.add_recognizer(first_name_recognizer)

last_name_list = get_records("last_name")
last_name_recognizer = PatternRecognizer(
    supported_entity="LAST_NAME",
    deny_list=last_name_list,
    context=["name", "last name", "surname", "family name"]
)
analyzer.registry.add_recognizer(last_name_recognizer)

swift_list = get_records("swift")
swift_recognizer = PatternRecognizer(
    supported_entity="SWIFT_CODE",
    deny_list=swift_list,
    context=["swift", "bank code", "bic"]
)
analyzer.registry.add_recognizer(swift_recognizer)

# JWT token pattern recognition
jwt_pattern = Pattern(
    name="jwt_pattern",
    regex=r"^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$",
    score=0.9
)
jwt_list = get_records("jwt")
jwt_recognizer = PatternRecognizer(
    supported_entity="JWT",
    deny_list=jwt_list,
    patterns=[jwt_pattern],
    context=["JWT","jwt","token","jwt_token","JWT_TOKEN"]
)
analyzer.registry.add_recognizer(jwt_recognizer)

# Salary pattern recognition
salary_pattern = Pattern(
    name="salary_pattern",
    regex = r"[$€£¥₹]\d{1,3}(,\d{3})*(\.\d{2})?",
    score=0.9
)
salary_list = get_records("salary")
salary_recognizer = PatternRecognizer(
    supported_entity="SALARY",
    deny_list=salary_list,
    context=["salary", "income", "pay", "wage"],
    patterns=[salary_pattern]
)
analyzer.registry.add_recognizer(salary_recognizer)

def print_analyzer_results(results, text, threshold=0.4):
    """Print analysis results with sensitivity classification for scores above threshold."""
    sensitivity="LOW"
    for i, result in enumerate(results):
        if result.score is not None and result.score > threshold:
          if result.entity_type in highly_sensitive:
            sensitivity="HIGH"
          elif result.entity_type in moderately_sensitive:
            sensitivity="MODERATE"
          else:
            sensitivity="LOW"

          print(f"Result {i}:")
          print(f" {result}, text: {text[result.start:result.end]}, Sensitivity:{sensitivity}")
          if result.analysis_explanation is not None:
            print(f" {result.analysis_explanation.textual_explanation}")

def extract_text_from_file(file_path):
    """Extract plain text content from supported file formats (TXT, JSON, DOCX, PDF)."""
    _, ext = os.path.splitext(file_path.lower())

    try:
        if ext == ".txt":
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()

        elif ext == ".json":
            with open(file_path, "r", encoding="utf-8") as f:
                content = json.load(f)
                return json.dumps(content, indent=2)  # or extract specific fields if needed

        elif ext == ".docx":
            doc = Document(file_path)
            return "\n".join([para.text for para in doc.paragraphs])

        elif ext == ".pdf":
            text = ""
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text += page.extract_text() + "\n"
            return text

        else:
            raise ValueError("Unsupported file format.")

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return ""


def call_presidio(file_content):
    """Analyze file content using Presidio and print results with sensitivity classification."""
    analyzer_results = analyzer.analyze(text=file_content,language="en")
    print_analyzer_results(analyzer_results,file_content,threshold=0.6)

