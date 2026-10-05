"""Unit tests for pluggable sensitive data detectors and detector engine."""

import pytest

from gateway.detectors.api_key import ApiKeyDetector, shannon_entropy
from gateway.detectors.base import DetectionSpan, EntityType
from gateway.detectors.credit_card import CreditCardDetector, luhn_checksum
from gateway.detectors.email import EmailDetector
from gateway.detectors.engine import DetectorEngine
from gateway.detectors.gov_id import GovIdDetector
from gateway.detectors.iban import IBANDetector, validate_iban
from gateway.detectors.ip_address import IpAddressDetector
from gateway.detectors.person_name import PersonNameDetector
from gateway.detectors.phone import PhoneDetector


class TestBaseModels:
    def test_detection_span_validation(self):
        span = DetectionSpan(
            entity_type=EntityType.EMAIL,
            start=0,
            end=10,
            text="user@a.com",
            confidence=0.9,
            detector_name="test",
        )
        assert span.overlaps_with(
            DetectionSpan(
                entity_type=EntityType.EMAIL,
                start=5,
                end=15,
                text="a.com/path",
                confidence=0.5,
                detector_name="test",
            )
        )
        assert not span.overlaps_with(
            DetectionSpan(
                entity_type=EntityType.EMAIL,
                start=12,
                end=20,
                text="other",
                confidence=0.5,
                detector_name="test",
            )
        )

    def test_invalid_span_bounds(self):
        with pytest.raises(ValueError):
            DetectionSpan(
                entity_type=EntityType.EMAIL,
                start=-1,
                end=10,
                text="x",
                confidence=0.5,
                detector_name="test",
            )
        with pytest.raises(ValueError):
            DetectionSpan(
                entity_type=EntityType.EMAIL,
                start=10,
                end=5,
                text="x",
                confidence=0.5,
                detector_name="test",
            )
        with pytest.raises(ValueError):
            DetectionSpan(
                entity_type=EntityType.EMAIL,
                start=0,
                end=5,
                text="x",
                confidence=1.5,
                detector_name="test",
            )


class TestEmailDetector:
    def setup_method(self):
        self.detector = EmailDetector()

    def test_standard_email(self):
        text = "Contact support at alice.smith@example.org for assistance."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].text == "alice.smith@example.org"
        assert spans[0].entity_type == EntityType.EMAIL
        assert spans[0].subtype == "standard"

    def test_obfuscated_email(self):
        text = "Send your resume to john dot doe at gmail dot com immediately."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.EMAIL
        assert spans[0].subtype == "obfuscated"

    def test_clean_text_no_false_positive(self):
        text = "Meet me at noon in the cafeteria. Server is at 10.0.0.15."
        spans = self.detector.detect(text)
        assert len(spans) == 0


class TestCreditCardDetector:
    def setup_method(self):
        self.detector = CreditCardDetector()

    def test_luhn_checksum_logic(self):
        assert luhn_checksum("4532015112830366") is True  # Valid Visa
        assert luhn_checksum("4532015112830367") is False  # Invalid check digit
        assert luhn_checksum("123") is False  # Too short

    def test_valid_credit_cards_and_brands(self):
        # Visa
        text_visa = "Visa: 4532-0151-1283-0366"
        spans_visa = self.detector.detect(text_visa)
        assert len(spans_visa) == 1
        assert spans_visa[0].subtype == "visa"

        # Mastercard (51-55 prefix)
        text_mc = "Mastercard: 5425-2334-3010-9903"
        spans_mc = self.detector.detect(text_mc)
        assert len(spans_mc) == 1
        assert spans_mc[0].subtype == "mastercard"

        # Amex (34/37 prefix, 15 digits)
        text_amex = "Amex: 3782 822463 10005"
        spans_amex = self.detector.detect(text_amex)
        assert len(spans_amex) == 1
        assert spans_amex[0].subtype == "amex"

    def test_invalid_card_rejected_by_luhn(self):
        text = "Fake card number 4532-0151-1283-0367 should fail Luhn."
        spans = self.detector.detect(text)
        assert len(spans) == 0

    def test_repeating_digits_rejected(self):
        text = "0000-0000-0000-0000"
        spans = self.detector.detect(text)
        assert len(spans) == 0


class TestIBANDetector:
    def setup_method(self):
        self.detector = IBANDetector()

    def test_iban_validation_logic(self):
        assert validate_iban("DE89370400440532013000") is True
        assert validate_iban("DE89 3704 0044 0532 0130 00") is True
        assert validate_iban("DE89370400440532013001") is False  # Bad checksum
        assert validate_iban("SHORT") is False

    def test_detect_iban_in_text(self):
        text = "Transfer the invoice payment to DE89 3704 0044 0532 0130 00."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.IBAN
        assert spans[0].subtype == "iban_de"


class TestGovIdDetector:
    def setup_method(self):
        self.detector = GovIdDetector()

    def test_us_ssn(self):
        text = "Applicant SSN is 123-45-6789."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].text == "123-45-6789"
        assert spans[0].subtype == "us_ssn"

    def test_invalid_us_ssn_prefixes(self):
        text = "Invalid SSNs: 000-45-6789, 666-45-6789, 912-45-6789."
        spans = self.detector.detect(text)
        assert len(spans) == 0

    def test_indian_pan(self):
        text = "Taxpayer PAN number: ABCDE1234F and AAAPA1234F"
        spans = self.detector.detect(text)
        assert len(spans) == 2
        assert spans[0].subtype == "in_pan"
        assert spans[1].subtype == "in_pan"

    def test_uk_nino(self):
        text = "National insurance number: QQ 12 34 56 A and JH 98 76 54 C"
        spans = self.detector.detect(text)
        assert len(spans) == 2
        assert spans[0].subtype == "uk_nino"
        assert spans[1].subtype == "uk_nino"


class TestApiKeyDetector:
    def setup_method(self):
        self.detector = ApiKeyDetector()

    def test_shannon_entropy(self):
        assert shannon_entropy("") == 0.0
        # Highly repetitive string has low entropy
        low_entropy = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")
        assert low_entropy == 0.0
        # High entropy random string
        high_entropy = shannon_entropy("8fJ#9kL!mQ2$xZ8*pW4&vN1@")
        assert high_entropy > 3.8

    def test_openai_api_key(self):
        text = "export OPENAI_API_KEY='sk-abcdefghijklmnopqrstuvwxyz1234567890'"
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.API_KEY
        assert "sk-" in spans[0].text

    def test_github_token(self):
        text = "GitHub PAT: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].subtype == "github_pat"

    def test_aws_access_key(self):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].subtype == "aws_access_key"

    def test_generic_high_entropy_token(self):
        token = "9bK7xM2pQ4wZ8vL1rT5nY0eS3aF6"
        text = f'auth_token: "{token}"'
        spans = self.detector.detect(text)
        assert len(spans) >= 1

    def test_lookalike_negatives_rejected(self):
        text = """
        UUID: 550e8400-e29b-41d4-a716-446655440000
        Commit: 7a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b
        Order: ORD-98234-X
        Variable: customer_payment_status_record_entry
        Camel: myInternalSystemConfigurationHandler
        """
        spans = self.detector.detect(text)
        assert len(spans) == 0


class TestPhoneDetector:
    def setup_method(self):
        self.detector = PhoneDetector()

    def test_us_phone_formats(self):
        text = "Call us at (555) 234-5678 or 555-345-6789."
        spans = self.detector.detect(text)
        assert len(spans) == 2
        assert all(s.entity_type == EntityType.PHONE for s in spans)

    def test_international_phone_format(self):
        text = "International hotline is +44 20 7946 0958."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].subtype == "international"


class TestIpAddressDetector:
    def setup_method(self):
        self.detector = IpAddressDetector()

    def test_valid_ipv4(self):
        text = "Database server is listening on 192.168.1.100."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].text == "192.168.1.100"
        assert spans[0].entity_type == EntityType.IP_ADDRESS

    def test_invalid_octets_ignored(self):
        text = "Invalid IP addresses: 999.999.999.999 or 256.1.2.3"
        spans = self.detector.detect(text)
        assert len(spans) == 0


class TestPersonNameDetector:
    def setup_method(self):
        self.detector = PersonNameDetector(use_nlp=False)

    def test_honorific_name(self):
        text = "Please reach out to Dr. Gregory House regarding patient care."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert "Gregory House" in spans[0].text
        assert spans[0].entity_type == EntityType.PERSON_NAME

    def test_contextual_intro(self):
        text = "Customer name: Alice Johnson requested an account refund."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert "Alice Johnson" in spans[0].text

    def test_city_names_filtered(self):
        text = "We visited New York and San Francisco."
        spans = self.detector.detect(text)
        assert len(spans) == 0


class TestDetectorEngine:
    def setup_method(self):
        self.engine = DetectorEngine(include_ner=True)

    def test_multiple_entities_in_one_prompt(self):
        prompt = (
            "Hello, my name is Dr. Alice Walker. My email is alice@company.com and "
            "my credit card is 4532-0151-1283-0366. Server is at 10.0.0.15."
        )
        spans = self.engine.detect_all(prompt)
        entity_types = [s.entity_type for s in spans]
        assert EntityType.EMAIL in entity_types
        assert EntityType.CREDIT_CARD in entity_types
        assert EntityType.IP_ADDRESS in entity_types
        assert EntityType.PERSON_NAME in entity_types

    def test_ner_toggle(self):
        engine_no_ner = DetectorEngine(include_ner=False)
        text = "Dr. Alice Walker requested assistance."
        spans_no_ner = engine_no_ner.detect_all(text)
        assert len(spans_no_ner) == 0

        engine_with_ner = DetectorEngine(include_ner=True)
        spans_ner = engine_with_ner.detect_all(text)
        assert len(spans_ner) >= 1

    def test_resolve_overlaps_priority(self):
        # Empty spans
        assert DetectorEngine.resolve_overlaps([]) == []
