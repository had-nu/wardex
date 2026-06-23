# Config Profiles for Wardex Evaluate

Each file below tests a different organisational risk posture against
`test/usability/vulns.yaml`. Run with:

    wardex evaluate \
      --config test/usability/configs/<profile>.yaml \
      --evidence test/usability/vulns.yaml \
      frameworks/iso27001/*.yml

## Profiles

| Profile | Risk Appetite | Compensating | Internet | Auth | Expected BLOCK count |
|---------|---------------|-------------|----------|------|---------------------|
| high-security | 0.3 | none | yes | no | 5 |
| default | 0.6 | 80% | yes | yes | 0 |
| low-security | 1.2 | 50% | yes | yes | 0 |
| aggregate | 0.5 (limit 2.0) | none | yes | no | varies |
