import json
import csv
import re
from typing import Dict, Tuple, Any

class PIIDetector:
    def __init__(self):
        # Patterns for standalone PII
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]{1}\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b|\b\d{10}@\w+\b')
        
    def detect_standalone_pii(self, value: str) -> bool:
        if isinstance(value, str):
            if (self.phone_pattern.search(value) or 
                self.aadhar_pattern.search(value) or 
                self.passport_pattern.search(value) or 
                self.upi_pattern.search(value)):
                return True
        return False
    
    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> bool:
        combinatorial_flags = {
            'name': False,
            'email': False,
            'address': False,
            'device_ip': False
        }
        
        for key, value in data.items():
            if isinstance(value, str):
                if key == 'name' and ' ' in value and len(value.split()) >= 2:
                    combinatorial_flags['name'] = True
                if key == 'email' and '@' in value:
                    combinatorial_flags['email'] = True
                if key == 'address' and any(term in value.lower() for term in ['road', 'street', 'lane', 'avenue', 'nagar']):
                    combinatorial_flags['address'] = True
                if key in ['device_id', 'ip_address']:
                    combinatorial_flags['device_ip'] = True
        
        return sum(combinatorial_flags.values()) >= 2
    
    def redact_value(self, key: str, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if key == 'phone' and self.phone_pattern.search(value):
            return value[:2] + 'XXXXXX' + value[-2:]
        if key == 'aadhar' and self.aadhar_pattern.search(value):
            return 'XXXX XXXX ' + value[-4:]
        if key == 'passport' and self.passport_pattern.search(value):
            return value[0] + 'XXXXXXX'
        if key == 'upi_id' and self.upi_pattern.search(value):
            if '@' in value:
                username, domain = value.split('@', 1)
                return username[:2] + 'XXX@' + domain
            return value[:2] + 'XXXXXX' + value[-4:]
        if key == 'name' and ' ' in value:
            parts = value.split()
            return parts[0][0] + 'XXX ' + parts[-1][0] + 'XXX'
        if key == 'email' and '@' in value:
            username, domain = value.split('@', 1)
            return username[:2] + 'XXX@' + domain
        if key == 'address':
            pin_match = re.search(r'\b\d{6}\b', value)
            if pin_match:
                return f'[REDACTED_ADDRESS], {pin_match.group()}'
            return '[REDACTED_ADDRESS]'
        return value
    
    def process_record(self, record_id: int, data_json: str) -> Tuple[str, bool]:
        try:
            data = json.loads(data_json)
        except json.JSONDecodeError:
            return data_json, False
        
        has_pii = False
        redacted_data = {}
        
        for key, value in data.items():
            if self.detect_standalone_pii(str(value)):
                has_pii = True
                redacted_data[key] = self.redact_value(key, value)
            else:
                redacted_data[key] = value
        
        if not has_pii and self.detect_combinatorial_pii(data):
            has_pii = True
            for key, value in redacted_data.items():
                if key in ['name', 'email', 'address', 'device_id', 'ip_address']:
                    redacted_data[key] = self.redact_value(key, value)
        
        return json.dumps(redacted_data), has_pii

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detector.py input.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "redacted_output.csv"
    
    detector = PIIDetector()
    
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        
        for row in reader:
            record_id = int(row['record_id'])
            data_json = row['data_json']
            redacted_json, is_pii = detector.process_record(record_id, data_json)
            
            # ✅ only write rows where is_pii is True
            if is_pii:
                writer.writerow({
                    'record_id': record_id,
                    'redacted_data_json': redacted_json,
                    'is_pii': True
                })
    
    print(f"Processing complete. Only PII records saved to {output_file}")

if __name__ == "__main__":
    main()