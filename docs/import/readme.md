# Importing values

## Blacklists import from STIX JSON file

### Domain logic

Import procedure in application core works as follows

1. Filtering all values by object type, suitable types are `indicator`
    1. Filter all of those values by label, suitable labels are `misp:type="url"`, `misp:type="ip-dst"`
2. Format URLs object values to domain URNs
3. Save all values to database with defined types