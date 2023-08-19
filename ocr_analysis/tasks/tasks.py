import re

def extract_phone_numbers(text):
    phone_numbers = []
    pattern = r'(\+\d{1,2}\s?)?(\d{3}[\s-]?\d{3}[\s-]?\d{4}|\d{10})'
    
    matches = re.findall(pattern, text)
    # cases:   5394249505    //    539 422 9205     //     05394249505     //     +905329440505       //     0531 331 4151
    # TODO if there is a plus sign in the beginning, country detection can be made

    for match in matches:
        phone_number = ''.join(match)
        if re.match(r'\d{9}', phone_number) is None:
            phone_numbers.append(phone_number)
    
    return phone_numbers

def extract_id_numbers(text):
    id_numbers = []

    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'    # cases: 123-45-6789
    tc_pattern = r'\b\d{11}\b'                # cases: 12345678901

    ssn_matches = re.findall(ssn_pattern, text)
    tc_matches = re.findall(tc_pattern, text)

    for ssn in ssn_matches:
        id_numbers.append(("American SSN", ssn))
    
    for tc in tc_matches:
        id_numbers.append(("Turkish ID", tc))

    return id_numbers

def extract_credit_card_numbers(text):
    credit_card_numbers = []

    # Pattern for CREDIT_CARD_NUMBER
    cc_pattern = r'\b\d{4}-?\d{4}-?\d{4}-?\d{4}\b'

    cc_matches = re.findall(cc_pattern, text)

    credit_card_numbers.extend(cc_matches)

    return credit_card_numbers

def extract_plate_numbers(text):
    plate_numbers = []

    # Pattern for PLATE
    plate_pattern = r'\b[A-Z]{2}\d{2}-[A-Z]-\d{2,3}\b'

    plate_matches = re.findall(plate_pattern, text)

    plate_numbers.extend(plate_matches)

    return plate_numbers

def extract_dates(text):
    dates = []

    # Pattern for DATE (simple pattern, may need to be adjusted based on date formats)
    date_pattern = r'\b\d{2}/\d{2}/\d{4}\b'

    date_matches = re.findall(date_pattern, text)

    dates.extend(date_matches)

    return dates

def extract_emails(text):
    emails = []

    # Pattern for EMAIL
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

    email_matches = re.findall(email_pattern, text, re.IGNORECASE)

    emails.extend(email_matches)

    return emails

def extract_domains(text):
    domains = []

    # Pattern for DOMAIN
    domain_pattern = r'\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

    domain_matches = re.findall(domain_pattern, text)

    domains.extend(domain_matches)

    return domains

def extract_urls(text):
    urls = []

    # Pattern for URL
    url_pattern = r'\bhttps?://[^\s]+\b'

    url_matches = re.findall(url_pattern, text)

    urls.extend(url_matches)

    return urls

def extract_hashes(text):
    hashes = []

    # Pattern for HASH (using a simple pattern for demonstration purposes)
    hash_pattern = r'\b[A-Fa-f0-9]{32}\b'

    hash_matches = re.findall(hash_pattern, text)

    hashes.extend(hash_matches)

    return hashes

def detect_combolists(text):
    combolists = []

    # Pattern for COMBOLIST (simple pattern, may need to be adjusted based on the actual format)
    combolist_pattern = r'\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+\b'

    combolist_matches = re.findall(combolist_pattern, text)

    combolists.extend(combolist_matches)

    return combolists


def extract_sensitive_info(text):
    sensitive_info = {
        "phone_numbers": extract_phone_numbers(text),
        "id_numbers": extract_id_numbers(text),
        "credit_card_numbers": extract_credit_card_numbers(text),
        "plate_numbers": extract_plate_numbers(text),
        "dates": extract_dates(text),
        "emails": extract_emails(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "hashes": extract_hashes(text),
        "combolists": detect_combolists(text)
    }
    
    return sensitive_info

