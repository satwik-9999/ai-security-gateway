"""IP address detector with IPv4 boundary and octet validation."""

import ipaddress
import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


class IpAddressDetector(BaseDetector):
    name = "ip_address_detector"
    entity_type = EntityType.IP_ADDRESS

    # IPv4 candidate pattern: 4 dot-separated digit groups bounded by word boundaries
    IPV4_CANDIDATE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        for match in self.IPV4_CANDIDATE.finditer(text):
            candidate = match.group(1)

            # Check valid IP range
            try:
                ip_obj = ipaddress.IPv4Address(candidate)
                # Verify octet representation matches exactly (reject leading zeros like 012.034.056.078)
                if str(ip_obj) != candidate:
                    continue

                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=match.start(1),
                        end=match.end(1),
                        text=candidate,
                        confidence=0.95,
                        detector_name=self.name,
                        subtype="ipv4",
                    )
                )
            except ValueError:
                continue

        return spans
