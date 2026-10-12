"""Synthetic PII dataset generator using Faker with realistic phrasing, hard cases, and lookalikes."""

import json
import random
import uuid
from typing import Any, Dict, List
from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)


def generate_valid_credit_card() -> str:
    """Generate a 16-digit card number passing Luhn checksum."""
    digits = [4] + [random.randint(0, 9) for _ in range(14)]
    # Compute check digit
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 0:  # In full card this corresponds to doubled position
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    check_digit = (10 - (checksum % 10)) % 10
    digits.append(check_digit)
    raw = "".join(str(d) for d in digits)
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:]}"


def generate_valid_iban() -> str:
    """Generate a realistic valid German IBAN passing mod 97."""
    bank_code = "37040044"
    account = f"{random.randint(1000000000, 9999999999)}"
    # Calculate checksum: DE00 + bank_code + account -> rearranged: bank_code + account + 131400 (DE=1314)
    numeric_str = bank_code + account + "131400"
    checksum = 98 - (int(numeric_str) % 97)
    check_str = f"{checksum:02d}"
    return f"DE{check_str} {bank_code[:4]} {bank_code[4:]} {account[:4]} {account[4:8]} {account[8:]}"


def generate_synthetic_dataset(total_prompts: int = 550) -> List[Dict[str, Any]]:
    dataset: List[Dict[str, Any]] = []

    # Distribution:
    # ~150 clean prompts (some with lookalike negatives)
    # ~400 sensitive prompts across entity types and hard cases

    # 1. Clean prompts with lookalike negatives (UUIDs, git hashes, order IDs, version numbers)
    for i in range(150):
        prompt_type = i % 5
        if prompt_type == 0:
            prompt = (
                f"Can you explain the architecture diagram for microservice '{fake.bs()}'? "
                f"The order tracking format is ORD-{random.randint(1000,9999)}-X."
            )
        elif prompt_type == 1:
            commit = "".join(random.choices("0123456789abcdef", k=40))
            prompt = (
                f"Review this pull request git commit {commit}. "
                f"We refactored the class UserProfileHandler and variable user_auth_token_status_flag."
            )
        elif prompt_type == 2:
            uid = str(uuid.uuid4())
            prompt = (
                f"Here is the database entity UUID {uid}. "
                f"Ensure the software version check allows updates past v1.2.3.4."
            )
        elif prompt_type == 3:
            prompt = (
                f"Let's meet at noon in conference room {random.randint(100, 999)} to discuss "
                f"dot product optimizations and linear algebra transformations."
            )
        else:
            prompt = fake.paragraph(nb_sentences=3)

        dataset.append({
            "id": f"prompt_clean_{i+1:03d}",
            "text": prompt,
            "is_sensitive": False,
            "entities": []
        })

    # 2. Prompts containing sensitive entities
    entity_configs = [
        ("EMAIL", 50),
        ("PHONE", 50),
        ("CREDIT_CARD", 50),
        ("IBAN", 50),
        ("GOV_ID", 50),
        ("API_KEY", 50),
        ("IP_ADDRESS", 50),
        ("PERSON_NAME", 50),
    ]

    counter = 0
    for entity_type, count in entity_configs:
        for _ in range(count):
            counter += 1
            if entity_type == "EMAIL":
                # Mix standard and obfuscated emails (hard case)
                if counter % 2 == 0:
                    user_clean = fake.user_name()
                    val = f"{user_clean} dot support at {fake.domain_word()} dot com"
                    text = f"Customer ticket inquiry: please route the refund notification to {val} right away."
                else:
                    val = fake.email()
                    text = f"Support ticket #{random.randint(10000, 99999)}: Reach out to user at {val} for diagnostic logs."
            elif entity_type == "PHONE":
                val = f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}"
                text = f"Client requested callback regarding billing questions at {val}."
            elif entity_type == "CREDIT_CARD":
                # Mix standard dashed and spaced/split card numbers (hard case)
                card_num = generate_valid_credit_card()
                if counter % 2 == 0:
                    val = card_num.replace("-", " ")
                    text = f"Process manual merchant charge for card number {val} expires next month."
                else:
                    val = card_num
                    text = f"Urgent transaction dispute on Visa card {val}."
            elif entity_type == "IBAN":
                val = generate_valid_iban()
                text = f"Wire the quarterly vendor invoice payment to beneficiary IBAN {val}."
            elif entity_type == "GOV_ID":
                # SSN, PAN, UK NINO
                sub = counter % 3
                if sub == 0:
                    val = f"{random.randint(100,899):03d}-{random.randint(10,99):02d}-{random.randint(1000,9999):04d}"
                    text = f"Loan application review: applicant Social Security Number is {val}."
                elif sub == 1:
                    letters = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3))
                    val = f"{letters}PA{random.randint(1000,9999)}F"
                    text = f"Tax identity verification for Indian entity with PAN {val}."
                else:
                    val = f"QQ {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)} A"
                    text = f"Employee benefits record shows UK National Insurance Number {val}."
            elif entity_type == "API_KEY":
                # Mix openai sk-, github ghp_, and keys inside code blocks (hard case)
                sub = counter % 3
                if sub == 0:
                    val = f"sk-proj-{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=40))}"
                    text = f"Here is the OpenAI production key for deployment: {val}"
                elif sub == 1:
                    val = f"ghp_{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=36))}"
                    text = f"GitHub token for automated CI pipeline is {val}"
                else:
                    val = f"AKIA{''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=16))}"
                    text = f"```json\n{{\"aws_access_key\": \"{val}\"}}\n```"
            elif entity_type == "IP_ADDRESS":
                val = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                text = f"Database replica connection error at host {val} port 5432."
            elif entity_type == "PERSON_NAME":
                val = f"Dr. {fake.first_name()} {fake.last_name()}"
                text = f"Patient medical record intake confirmed by attending physician {val}."

            dataset.append({
                "id": f"prompt_sensitive_{counter:03d}",
                "text": text,
                "is_sensitive": True,
                "entities": [{"type": entity_type, "value": val}]
            })

    return dataset


if __name__ == "__main__":
    data = generate_synthetic_dataset(550)
    out_path = "eval/data/synthetic_pii_dataset.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {len(data)} synthetic prompts in {out_path}")
