import re

class SensitiveInfoExtractor:
    def __init__(self, text):
        self.text = text

    def extract_phone_numbers(self):
        phone_numbers = []
        pattern = r'(\+\d{1,2}\s?)?(\d{3}[\s-]?\d{3}[\s-]?\d{4}|\d{10})'
        
        matches = re.findall(pattern, self.text)
        # cases:   5394249505    //    539 422 9205     //     05394249505     //     +905329440505       //     0531 331 4151
        # TODO if there is a plus sign in the beginning, country detection can be made

        for match in matches:
            phone_number = ''.join(match)
            if re.match(r'\d{9}', phone_number) is None:
                phone_numbers.append(phone_number)
        
        return phone_numbers

    def extract_id_numbers(self):
        id_numbers = []

        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        tc_pattern = r'\b\d{11}\b'

        ssn_matches = re.findall(ssn_pattern, self.text)
        tc_matches = re.findall(tc_pattern, self.text)

        for ssn in ssn_matches:
            id_numbers.append(("American SSN", ssn))
        
        for tc in tc_matches:
            id_numbers.append(("Turkish ID", tc))

        return id_numbers

    def extract_credit_card_numbers(self):
        credit_card_numbers = []

        cc_pattern = r'\b\d{4}-?\d{4}-?\d{4}-?\d{4}\b'
        cc_matches = re.findall(cc_pattern, self.text)
        credit_card_numbers.extend(cc_matches)

        return credit_card_numbers

    def extract_plate_numbers(self):
        plate_numbers = []

        plate_pattern = r'\b[A-Z]{2}\d{2}-[A-Z]-\d{2,3}\b'
        plate_matches = re.findall(plate_pattern, self.text)
        plate_numbers.extend(plate_matches)

        return plate_numbers

    def extract_dates(self):
        dates = []

        date_pattern = r'\b\d{2}/\d{2}/\d{4}\b'
        date_matches = re.findall(date_pattern, self.text)
        dates.extend(date_matches)

        return dates

    def extract_emails(self):
        emails = []

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        email_matches = re.findall(email_pattern, self.text, re.IGNORECASE)
        emails.extend(email_matches)

        return emails

    def extract_domains(self):
        domains = []

        domain_pattern = r'\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        domain_matches = re.findall(domain_pattern, self.text)
        domains.extend(domain_matches)

        return domains

    def extract_urls(self):
        urls = []

        url_pattern = r'\bhttps?://[^\s]+\b'
        url_matches = re.findall(url_pattern, self.text)
        urls.extend(url_matches)

        return urls

    def extract_hashes(self):
        hashes = []

        hash_pattern = r'\b[A-Fa-f0-9]{32}\b'
        hash_matches = re.findall(hash_pattern, self.text)
        hashes.extend(hash_matches)

        return hashes

    def detect_combolists(self):
        combolists = []

        combolist_pattern = r'\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+\b'
        combolist_matches = re.findall(combolist_pattern, self.text)
        combolists.extend(combolist_matches)

        return combolists

    def extract_gender_info(self):
        gender_info = []

        gender_pattern = r'\b(?:male|female|woman|man|boy|girl)\b'
        gender_matches = re.findall(gender_pattern, self.text, re.IGNORECASE)
        gender_info.extend(gender_matches)

        return gender_info

    def extract_ip_addresses(self):
        ip_addresses = []

        ip_pattern = r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        ip_matches = re.findall(ip_pattern, self.text)
        ip_addresses.extend(ip_matches)

        return ip_addresses

    def format_findings(self, info_list, info_type):
        formatted_info = []
        for value in info_list:
            formatted_info.append({"value": value, "type": info_type})
        return formatted_info

    def extract_sensitive_info(self):
        sensitive_info = {
            "phone_numbers": self.format_findings(self.extract_phone_numbers(), "PHONE_NUMBER"),
            "id_numbers": self.format_findings(self.extract_id_numbers(), "ID_NUMBER"),
            "credit_card_numbers": self.format_findings(self.extract_credit_card_numbers(), "CREDIT_CARD"),
            "plate_numbers": self.format_findings(self.extract_plate_numbers(), "PLATE"),
            "dates": self.format_findings(self.extract_dates(), "DATE"),
            "emails": self.format_findings(self.extract_emails(), "EMAIL"),
            "domains": self.format_findings(self.extract_domains(), "DOMAIN"),
            "urls": self.format_findings(self.extract_urls(), "URL"),
            "hashes": self.format_findings(self.extract_hashes(), "HASH"),
            "combolists": self.format_findings(self.detect_combolists(), "COMBOLIST"),
            "gender": self.format_findings(self.extract_gender_info(), "GENDER"),
            "ip_addresses": self.format_findings(self.extract_ip_addresses(), "IP_ADDRESS")

        }
        
        return sensitive_info