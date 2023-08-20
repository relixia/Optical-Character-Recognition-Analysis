from validators import url as validate_url, domain as validate_domain
import whois
from utilities.helper_validator import luhn_algorithm_validation, detect_card_type, hunterio, verifalia


def validate_urls(urls):
    validated_urls = []
    for url in urls:
        if validate_url(url["value"]):
            url["validation"] = "valid"
        else:
            url["validation"] = "invalid"
        validated_urls.append(url)
    return validated_urls

def validate_domains(domains):
    validated_domains = []
    for domain in domains:
        if validate_domain(domain["value"]):
            domain["validation"] = "valid"

            try:
                domain_info = whois.whois(domain["value"])
                domain["registrar"] = domain_info.registrar
            except Exception as e:
                domain["registrar"] = "Unknown"

        else:
            domain["validation"] = "invalid"
            domain["registrar"] = "N/A"
        validated_domains.append(domain)
    return validated_domains

def validate_credit_cards(credit_cards):
    validated_card_numbers = []
    for card in credit_cards:
        card_number = card["value"].replace("-", "")
        
        # Luhn Algorithm Validation
        if luhn_algorithm_validation(card_number):
            card["luhn_validation"] = "valid"
        else:
            card["luhn_validation"] = "invalid"
        
        # Bin List Detection
        card_type = detect_card_type(card_number)
        card["bin_list_detection"] = card_type
        
        validated_card_numbers.append(card)
    
    return validated_card_numbers

def validate_emails(emails):
    validated_emails = []
    for email in emails:
        user_email = email["value"]

        # Hunter.io Validation
        hunter_result = hunterio(user_email)
        email["hunterio_verification"] = hunter_result

        # Verifalia Validation
        verifalia_result = verifalia(user_email)
        email["verifalia_verification"] = verifalia_result

        validated_emails.append(email)
    
    return validated_emails

def validate_fields(sensitive_info):
    fields = ["urls", "domains", "credit_card_numbers", "emails"]
    validation_functions = {
        "urls": validate_url,
        "domains": validate_domain,
        "credit_card_numbers": validate_credit_cards,
        "emails": validate_emails
    }
    
    validation_results = {}
    
    for field in fields:
        if field in sensitive_info and field in validation_functions:
            validation_results[field] = validation_functions[field](sensitive_info[field])
    
    return validation_results