# Compliance Evidence Foundation

FactoryLine can emit OSCAL-shaped assessment evidence from explicit receipt
control ids:

```powershell
factory compliance packs
factory compliance export nist-ssdf evidence.json `
  --tenant acme --out assessment.json
```

The built-in packs are FactoryLine-owned baseline mappings for NIST SSDF,
OWASP ASVS, SOC 2, and ISO 27001. They are not complete implementations of
those standards and do not confer certification. Every export says
`not-a-certification`; an auditor or customer must review the mapping,
evidence, scope, and operating context.

Use the `customer` pack with a reviewed JSON array of `{id, title, evidence}`
controls to add customer-specific requirements without changing the standard
packs.

