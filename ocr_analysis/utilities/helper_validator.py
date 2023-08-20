import json
import requests
from config import settings

def luhn_algorithm_validation(number):
    # Reverse the credit card number and convert it to a list of integers
    digits = [int(x) for x in str(number)][::-1]
    # Luhn algorithm
    total = sum(digits[0::2]) + sum(sum(divmod(d * 2, 10)) for d in digits[1::2])
    # If the total modulo 10 equals 0, the credit card number is valid
    return total % 10 == 0

def detect_card_type(card_number):
    card_type_mapping = {
        "37": "Amex",
        "4": "Visa",
        "51": "MasterCard",
        "52": "MasterCard",
        "53": "MasterCard",
        "54": "MasterCard",
        "55": "MasterCard",
        "300": "Diners Club",
        "301": "Diners Club",
        "302": "Diners Club",
        "303": "Diners Club",
        "304": "Diners Club",
        "305": "Diners Club",
        "36": "Diners Club",
        "38": "Diners Club",
        "6011": "Discover",
        "65": "Discover",
        "35": "JCB"
    }

    return next((card_type for prefix, card_type in card_type_mapping.items() if card_number.startswith(prefix)), "Unknown")

def hunterio(user_email: str) -> str:
    url = f"https://api.hunter.io/v2/email-verifier?email={user_email}&api_key={settings.HUNTERIO_API}"
    response = requests.get(url)
    return response.json()

def verifalia(user_email: str) -> str:
    url = "https://api.verifalia.com/v2.4/email-validations"
    headers = {
        "Content-Type": "application/json"
    }
    payload = { "entries": [ { "inputData": user_email } ] }
    response = requests.post(url, json=payload, headers=headers, auth=(settings.VERIFALIA_USERNAME, settings.VERIFALIA_PASSWORD))
    response_data = response.json()
    return response_data
