import whois
from validators import domain as validate_domain
from validators import url as validate_url
from validators import hashes as validate_hash
from validators import btc_address as validate_btc_wallet
from validators import iban as validate_iban

from utilities.helper_validator import (detect_card_type, hunterio,
                                        luhn_algorithm_validation, verifalia)


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

def validate_plate(plate_numbers):
    validated_plate_numbers = []
    for plate in plate_numbers:
        plate_number = plate["value"]

        first_two_digits = int(plate_number[:2])

        if 1 <= first_two_digits <= 81:
            plate["validation"] = "valid"
        else:
            plate["validation"] = "invalid"

        validated_plate_numbers.append(plate)

    return validated_plate_numbers


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

def validate_hashes(hashes):
    validated_hashes = []
    for hash_value in hashes:
        if validate_hash(hash_value["value"]):
            hash_value["validation"] = "valid"
        else:
            hash_value["validation"] = "invalid"
        validated_hashes.append(hash_value)
    return validated_hashes

def validate_id(id_numbers):
    validated_id_numbers = []
    for id_number in id_numbers:
        tc_number = id_number["value"]
        
        if len(tc_number) != 11 or not tc_number.isdigit():
            id_number["validation"] = "invalid"
        else:
            digits = [int(digit) for digit in tc_number]
            
            if digits[0] == 0:
                id_number["validation"] = "invalid"
            else:
                odd_sum = sum(digits[0:9:2])
                even_sum = sum(digits[1:8:2])
                check_digit_10 = (odd_sum * 7 - even_sum) % 10
                check_digit_11 = (sum(digits) - digits[10]) % 10
                
                if check_digit_10 == digits[9] and check_digit_11 == digits[10]:
                    id_number["validation"] = "valid"
                else:
                    id_number["validation"] = "invalid"
        
        validated_id_numbers.append(id_number)
    
    return validated_id_numbers

def validate_ip_addresses(ip_addresses):
    validated_ip_addresses = []
    for ip in ip_addresses:
        ip_address = ip["value"]

        if validate_ip_address(ip_address):
            ip["validation"] = "valid"
        else:
            ip["validation"] = "invalid"

        validated_ip_addresses.append(ip)

    return validated_ip_addresses

def validate_btc_wallets(btc_wallets):
    validated_btc_wallets = []
    for wallet in btc_wallets:
        if validate_btc_wallet(wallet["value"]):
            wallet["validation"] = "valid"
        else:
            wallet["validation"] = "invalid"
        validated_btc_wallets.append(wallet)
    return validated_btc_wallets

def validate_iban(iban_numbers):
    validated_ibans = []
    for iban in iban_numbers:
        if validate_iban(iban["value"]): 
            iban["validation"] = "valid"
        else:
            iban["validation"] = "invalid"
        validated_ibans.append(iban)
    return validated_ibans

def validate_fields(sensitive_info):
    fields = ["urls", "domains", "credit_card_numbers", "emails"]
    validation_functions = {
        "urls": validate_url,
        "domains": validate_domain,
        "credit_card_numbers": validate_credit_cards,
        "emails": validate_emails,
        "hashes": validate_hashes,
        "id_numbers": validate_id,
        "plate_numbers": validate_plate,
        "ip_addresses": validate_ip_addresses,
        "btc_wallets": validate_btc_wallets,
        "ibans": validate_iban,
    }

    validation_results = {}

    for field in fields:
        if field in sensitive_info and field in validation_functions:
            validation_results[field] = validation_functions[field](
                sensitive_info[field]
            )

    return validation_results
