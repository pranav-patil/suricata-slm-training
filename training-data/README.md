# Suricata Training Data Generation

## Suricata Training Data Requirements

Suricata rule validation require training data set containing good and bad suricata rules. Suricata rule correction requires training data containing bad rules and corresponding fixed rule into good rules. Below are the required characteristics of the training data.

- Data Coverage: Cover all the content and reflect the distribution of formats/topics/difficulties.
- Data Quality
- Data Diversity (If possible real-world error diversity)
- Realistic Errors
- Avoid Noise (adds randomness and confusion, were model starts learning spurious or misleading patterns instead of clean, generalizable behavior)
- Avoid Duplication
- Ensure "Hard Negatives" Exists (provide syntactically perfect but logically bad rules e.g. with invalid protocol)
- Representative Evaluation Dataset
- Consistent Grading

**Semantic Deduplication** is the process of identifying and removing redundant data by analyzing the meaning (semantic content) of information, rather than just matching exact words or metadata. Unlike exact or fuzzy deduplication, which focus on textual similarity, semantic deduplication leverages the semantic meaning of the content to identify duplicates. It reduces [dataset size](https://arxiv.org/pdf/2303.09540) (upto 50%) while maintaining or even improving model performance. Refer to [Nemo Semantic Deduplication](https://docs.nvidia.com/nemo-framework/user-guide/24.12/datacuration/semdedup.html).

## Suricata Rule Updater

The `suricata-update` is the official rule management tool bundled with Suricata (and installable standalone). It parses rules, resolves flowbits, merges sources, and filters out syntactically broken rules for the Suricata version being used.
`suricata-update` can parse rules and drop ones with syntax errors for the version in use — effectively "upgrading" the active rule base by removing incompatible rules.

    pip install --upgrade suricata-update
    suricata-update -V

Discover the Suricata rule sources by updating the rule source index.

    suricata-update update-sources
    suricata-update list-sources

Generate new merged rule set

    suricata-update

Point to specific Suricata version

    suricata-update --suricata-version 8.0.3

Enable/Disable/Remove new ruleset sources

    suricata-update enable-source ptresearch/attackdetection
    suricata-update disable-source et/pro
    suricata-update remove-source et/pro


## Gather Suricata Training Data from Public Github

- [suricata-rules](https://github.com/daffainfo/suricata-rules)
- [OISF suricata](https://github.com/OISF/suricata)
- [quadrant-suricata.rules](https://github.com/quadrantsec/suricata-rules/blob/main/quadrant-suricata.rules)
- [seanlinmt suricata](https://github.com/seanlinmt/suricata)
- [sudohyak suricata-rules](https://github.com/sudohyak/suricata-rules)
- [opnsense-suricata-nmaps](https://github.com/aleksibovellan/opnsense-suricata-nmaps/blob/main/local.rules)
- [Suricata-Detect-DoS-Attack](https://github.com/arvindpj007/Suricata-Detect-DoS-Attack/blob/master/detect-dos.rules)
- [ARPSyndicate suricata-vedas](https://github.com/ARPSyndicate/suricata-vedas)
- [Suricata-Rules-for-ICS-SCADA Scan Rules](https://github.com/CyberICS/Suricata-Rules-for-ICS-SCADA/blob/main/scada-scan.rules)
- [Attack-Suricata-IDS-Rules](https://github.com/ajest983/Attack-Suricata-Rules/tree/main/Suricata%20IDS%20Rules)
- [Suricata_Threat-Hunting-Rules](https://github.com/Truvis/Suricata_Threat-Hunting-Rules/tree/master)
- [Suricata-IDS-IPS-NSM-engine](https://github.com/fredriclesomar/Suricata-IDS-IPS-NSM-engine)
- [SCS-Labs rules](https://github.com/SCS-Labs/rules)
- [URLhaus IDS ruleset](https://urlhaus.abuse.ch/downloads/suricata-ids/)
- [OpenInfoSec Foundation - Redmine](https://redmine.openinfosecfoundation.org/attachments/download/2035/suricata.rules.txt)
- [Proofpoint Emerging Threats Rules](https://rules.emergingthreats.net/)

References:
 - [AWS Sample Suricata Generator](https://github.com/aws-samples/sample-suricata-generator)
 - [Python Suricata Parser](https://github.com/m-chrome/py-suricataparser)

## Pre-Cleaning Raw Data

Remove blank and commented lines

    grep -v -E '^[[:space:]]*$|^[[:space:]]*#' main.rules > clean.rules

## Validate Suricate Rules using Suricata CLI

Install Suricata CLI

    brew install suricata
    suricata --build-info

Validate the suricata rules using Suricata CLI as below:

    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S good.rules

We can use the Suricata CLI validate script to split the rules file into good and bad rules:

    python3 scripts/validate_rules_cli.py clean_rules


## Validate Suricata Rules using create AWS Rule Group

Login into AWS account

    PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" aws-azure-login --mode=gui

    export AWS_ACCOUNT_ID=767044641253
    export AWS_REGION=us-east-1
    aws sts get-caller-identity --region ${AWS_REGION}

Using the AWS create rule group command determine if the suricata rule is valid using below python script

    python3 scripts/split_rules.py good.rules 3000
    python3 scripts/validate_rules_aws.py chunks
    python3 scripts/combine_chunks.py chunks -o good_perform.rules

## Validate Suricata Rule Performance using AWS Create Rule Group

Setup Poetry configuration

    poetry install

Poetry Setup to execute Create Rule Group (from PMR Code)

    poetry install

    poetry run python3 -c "import boto3; client = boto3.client('network-firewall', region_name='us-east-1'); print('start_rule_analysis' in dir(client))"

We can execute the create rulegroup using below command:

    poetry run python3 ./scripts/create_rule_group_minimal.py \
    --name EmproviseBlockStrictOrder \
    --order STRICT_ORDER \
    --rules ./suricatarules20251210_115.rules \
    --region us-east-1 \
    --wait 300

Note: The PMR Code requires that the rule `msg` starts with `EmproviseBlockStrictOrder: `. Hence replace `( msg:"` with `( msg:"EmproviseBlockStrictOrder: `.
Also PMR requires the ending brackets has no spaces e.g. `;)` instead of `; )`.

Split the rules file into multiple chunks with 2500 rules per chunk.

    chmod +x training-data/scripts/*.py

    cd training-data
    ./scripts/split_rules.py public_rules/4_good_refined.rules 2500
    ./scripts/analyze_chunks.sh ./chunks
    ./scripts/combine_chunks.py chunks -o good_perform.rules


### Check Common Rules in two files

Use the below `compare_rules.py` script to list common suricata rules between two files.

    python3 scripts/compare_rules.py bad_ext_net.rules bad_more.rules

To remove the common rules between the two from the second file passed as argument, use below command.

    python3 scripts/compare_rules.py bad_ext_net.rules bad_more.rules -remove


## Suricata Rule Diversification and Validation

Diversify the Suricata rules by shuffling the fields without altering the rule's logic, updating the sid, revision, port numbers and CIDR blocks or IP addresses using random data.

    python scripts/rule_randomizer.py good.rules

    find chunks -name "*.rules" -type f -exec python3 ./scripts/rule_randomizer.py {} \;

    mkdir chunks_random && mv chunks/chunk*_random.rules chunks_random/ && mv chunks chunks_original && mv chunks_random chunks && rm chunks_original/sids.txt

Randomize Bad rules

    cat public_rules/2_bad_cli.rules public_rules/3_bad_more.rules > combined_bad.rules

    python3 scripts/rule_randomizer.py combined_bad.rules


## Suricata Rule Performance Analysis

The performance of Suricata rules can be analyzed using Minimum/Maximum and Average CPU ticks. We need to build suricata from the source-code by setting `profiling.rules.enabled` to yes.

    cd scripts
    ./performance_check.sh ../emprovise_rules/local3.rules ../malware_pcaps/44723.pcap

## Fix Suricata Rules

The rule_fixer script is used for generating training data with bad rules as input and fixed rules as output which pass all Suricata checks & validation. It is generated from Suricata BNF grammer file.

    python scripts/rule_fixer.py public_rules/2_bad_cli.rules -o fixed.rules


## Generate Random Suricata Rules

Generate random suricata rules mostly bad rules for training data.

    python scripts/generate_rules.py -n 30000 -o random.rules

## Corrupt Good Suricata Rules

The rule_corrupter script is used for generating training data with bad rules as input and fixed rules as output which pass all Suricata checks & validation. It is generated from Suricata BNF grammer file.

    python scripts/rule_corrupter.py public_rules/4_good_performing.rules -o bad.rules

## Minify Python code

    python scripts/minify_py.py scripts/rule_fixer.py

## Rule Fixer Training Dataset

    cat public_rules/2_bad_cli.rules public_rules/3_bad_more.rules > dataset_rule_fix/combined_bad.rules

    python scripts/rule_fixer.py dataset_rule_fix/combined_bad.rules -o dataset_rule_fix/fixed.rules

    python scripts/rule_compressor.py dataset_rule_fix/fixed.rules

    python scripts/validate_rules_cli.py dataset_rule_fix/fixed_compressed.rules
    python scripts/split_rules.py dataset_rule_fix/good.rules 3000
    python scripts/validate_rules_aws.py chunks
    python scripts/combine_chunks.py chunks -o good_valid.rules

    python scripts/rule_corrupter.py dataset_rule_check/good_valid.rules -o dataset_rule_fix/good_corrupt.rules

## Rule Compressor

 - **PCRE:** The PCRE strings can be `Tries`, a highly optimized trees of domain names. They can be drastically reduced by pruning the tree: keeping the first branch of any alternation (`|`) and discarding the rest. This preserves the parentheses balance and the modifiers (like `/Hmi` or `/R`), ensuring the regex remains valid.
    - **Syntax Preservation:** The model still sees the `/^Host\:[^\r\n]+?\./` prefix and the `Hmi` or `R` modifiers. It learns that HTTP rules often look for specific host patterns.
    - **Token Efficiency:** Long, repetitive hex strings (`\x00\x57\x00...`) eat up tokens and cause the model to lose context. Shortening them allows the model to "focus" on the relationship between the Suricata keywords (like `content`, `pcre`, and `sid`).
    - **Validity:** Use a depth-aware parser to find the `|` symbol, so we never leave a parenthesis hanging open.

 - **Content:** We need to preserve the "bones" of the syntax: the **double quotes**, the **hex pipes** (`|00 00|`), and the **negation prefix** (`!`).
    - **Negation Preservation:** If a content starts with `!`, keep it.
    - **Hex Pruning:** Inside `| |` blocks, keep only the first 2 hex pairs (e.g., `|3c 64 69 76|` $\rightarrow$ `|3c 64|`).
    - **Text Truncation:** Keep only the first 5–8 characters of any plain text.
    - **Content Limiting:** If a rule has 10+ content matches, we keep only the first 3–4 to ensure the total rule length stays under 256 characters.

 - **Reference:** It is used to point to external security databases or URLs (e.g., `url`, `cve`, `bugtraq`, `md5`).
    - **Reduce the Count:** Keep only the first 1 or 2 reference entries.
    - **Truncate URLs:** Keep only the domain and a few characters of the path.
    - **Truncate Hashes:** Reduce MD5/SHA hashes to a shorter "representative" hex string.

 - **Metadata:** It provides excellent context for analysts, it is largely non-functional for the detection engine itself. Prioritize `structural` metadata (like affected_product or cve) and discard `verbose` metadata (like mitre_tactic_name).
    - **Vocabulary Reduction:** By removing specific dates and long product strings, the model's vocabulary remains focused on keywords like `affected_product` and `attack_target`.
 
 - **Address List:** Reduce the list of long IP Addresses from the Source or Destination addresses of the Suricata rule.

 - **Message:** Finds the shared word-based prefix, and compresses that prefix into a dynamic acronym (keeping the first vendor tag intact for context).

Below is the command to compress suricata rules file using `rule_compressor`.

    python scripts/rule_compressor.py dataset_rule_fix/good.rules

## Fuzzy Deduplication

Canonical Fingerprinting (Exact Structural Hashing) is the process which strips away the "noise" from the mutations to find the underlying structural logic of the rule.

 - **Header Masking**: We mask highly mutated fields (action, protocol, IPs, ports, direction) with generic placeholders.

 - **Robust Option Extraction**: We use a state-machine parser to safely split options without breaking payload strings containing escaped quotes or semicolons.

 - **Noise Filtering**: We remove options that do not impact syntax or AWS compatibility (like msg, sid, rev, metadata, reference).

 - **Alphabetical Sorting**: We sort the remaining options alphabetically. This completely neutralizes the "mutated order of rule options" tactic.

 - **Hashing**: We hash this normalized string to generate a unique structural fingerprint.

    python3 scripts/deduplicate.py -i dataset_rule_check/good.rules  -o dataset_rule_check/good_dedup.rules


## Format Suricata CLI Error Log

Sort similar suricata errors in the error logs.

    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S bad.rules 2> errors.log 

    python3 scripts/transform_errors.py errors.log



    rm good.rules bad.rules good_performing_random.rules public_rules/sids.txt

    python scripts/rule_randomizer.py /Users/emprovise/repositories/suricata-slm-training/training-data/public_rules/4_good_performing.rules

    mv public_rules/4_good_performing_random.rules good_performing_random.rules

    python scripts/validate_rules_cli.py good_performing_random.rules 

    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S bad.rules 

    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S bad.rules 2> errors.log 

