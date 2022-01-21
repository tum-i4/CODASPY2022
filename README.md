# CODASPY 2022

This repository is part of the paper *Hardening with Scapolite: a DevOps-based Approach for Improved Authoring and Testing of Security-Configuration Guides in Large-Scale Organizations* presented at the [**12<sup>th</sup> ACM Conference on Data and Application Security and Privacy (CODASPY)**](http://www.codaspy.org/2022/index.html).
We submitted our article as a full-length paper.
However, we had to convert it into a tool paper during the review process.
Thus, the version published under [DOI 10.1145/3508398.3511525](https://doi.org/10.1145/3508398.3511525) only consists of 6 pages, but one can download the original, full-length version [here](https://i4.pages.gitlab.lrz.de/conferences-public/preprints/2022/CODASPY/hardening-with-scapolite.pdf).

## Code Snippets

### The Scapolite Format

```md
---
scapolite:
    class: rule
    version: '0.51'
id: BL942-1101
id_namespace: org.scapolite.example
title: Configure use of passwords for removable data drives
rule: <see below>
implementations:
  - relative_id: '01'
    description: <see below>
history:
  - version: '1.0'
    action: created
    description: Added so as to mitigate risk SR-2018-0144.
---
## /rule
Enable the setting 'Configure use of passwords for removable
data drives' and set the options as follows:
   *  Select `Require password complexity`
   *  Set the option 'Minimum password length for removable data drive` to `15`.
## /implementations/0/description
To set the protection level to the desired state, enable the policy
`Computer Configuration\...\Configure use of passwords for removable data drives`
and set the options as specified above in the rule.
```

[This file](./code/1_basic_scapolite.md) contains a basic Scapolite file.
One can see the meta data in the YAML preamble and the text intended for humans in the markdown part.
This file is a reduced version of an actual Siemens security rule with the id *BL942-1101*.
One can find the original rule [here](./code/1_BL942-1101.md).

### Adding Machine-Readable Automations

```yaml
system: org.scapolite.implementation.win_gpo
ui_path: Computer Configuration\...\Configure use of passwords for removable data drives
value:
  main_setting: Enabled
  Configure password complexity for removable data drives: Require password complexity
  Minimum password length for removable data drive: 15
  constraints:
    Minimum password length for removable data drive:
      min: 15
```

[This file](./code/2_gpo_automation.yaml) contains a machine-readable automation to implement and check the rule *BL942-1101*.
In the [updated rule file](code/2_BL942-1101_automation.md), one can see how we include the automation in the rule.

### Transforming Automations

```yaml
system: org.scapolite.automation.compound
automations:
  - system: org.scapolite.implementation.windows_registry
    config: Computer
    registry_key: Software\Policies\Microsoft\FVE
    value_name: RDVPassphrase
    action: DWORD:1
  - system: org.scapolite.implementation.windows_registry
    config: Computer
    registry_key: Software\Policies\Microsoft\FVE
    value_name: RDVPassphraseComplexity
    action: DWORD:1
  - system: org.scapolite.implementation.windows_registry
    config: Computer
    registry_key: Software\Policies\Microsoft\FVE
    value_name: RDVPassphraseLength
    action: DWORD:15
    constraints:
        min: 15
```

Based on the machine-readable automation from the previous step, we can now generate the *low-level* [automations](code/3_generated_automation.yaml).
These automations represent the registry keys that we have to set to implement the rule, respectively to check for the given values if we want to assess a system for this rule.
In [the updated rule file](code/3_BL942-1101_generated_automation.md), one can see how we include the generated automations in the Scapolite file.

### Including Scripts

```yaml
system: org.scapolite.automation.script
script: |
    Get-Volume | Select Size, FileSystemType | Where {$_.Size -gt 1GB}
expected:
    output_processor: Format-List
    each_item:
      key: FileSystemType
      equal_to: NTFS
```

If we cannot find a suitable abstraction level, we must include code in a suitable scripting language.
For expressing checks, we can at least regain some abstraction via a generic method for expressing the expected output of check-scripts to keep the scripts included as `script automation` in the Scapolite document as concise as possible.
[This file](./code/3_script_example.yaml) shows an example of a check for the requirement that all mounted volumes larger than 1GB should use the NTFS file system.
In [the script rule file](code/3_BL696-0227.md), one can see how we include the script automation in the Scapolite file.

### Producing Code and Other Artifacts

```xml
<criteria negate="false" operator="AND">
  <criteria negate="false" operator="AND">
    <criterion negate="false" test_ref="oval:tst:105650">
      <win:registry_test check="all" check_existence="at_least_one_exists"  id="oval:tst:105650" version="1">
        <win:registry_object id="oval:obj:105650" version="1">
          <win:hive datatype="string" operation="equals">
            HKEY_LOCAL_MACHINE
          </win:hive>
          <win:key datatype="string" operation="case insensitive equals">
            Software\Policies\Microsoft\FVE
          </win:key>
          <win:name datatype="string" operation="equals">
            RDVPassphrase
          </win:name>
        </win:registry_object>
        <win:registry_state id="oval:ste:105650" version="1">
          <win:type datatype="string" operation="equals">
            reg_dword
          </win:type>
          <win:value datatype="int" entity_check="all" operation="equals">
            1
          </win:value>
        </win:registry_state>
      </win:registry_test>
    </criterion>
  </criteria>
  ...
</criteria>
```

As an example for a different *target* of our transformations, [this file](code/4_registry_automation_example_oval.xml) shows the result of a transformation from the [generated automations](code/3_generated_automation.yaml) into an OVAL check.
This particular transformation might look straightforward, but even simple checks can get complicated when expressed in OVAL;
combined with the verbose XML structure of OVAL and its many cross-references, generating OVAL was a prime use case for our code generation.

```json
{
    "BL942-1101_sub_0": {
        "action": "DWORD:1",
        "config": "Computer",
        "path": "Software\\Policies\\Microsoft\\FVE",
        "rule_name": "BL942-1101",
        "rule_type": "pol",
        "title": "Configure the policy Configure use of passwords for removable data drives",
        "type": "DWORD",
        "value": 1,
        "value_name": "RDVPassphrase",
        "acp": "C:123|I:123|A:123"
    },
    "BL942-1101_sub_1": {
        "action": "DWORD:1",
        "config": "Computer",
        "path": "Software\\Policies\\Microsoft\\FVE",
        "rule_name": "BL942-1101",
        "rule_type": "pol",
        "title": "Configure the policy Configure use of passwords for removable data drives",
        "type": "DWORD",
        "value": 1,
        "value_name": "RDVPassphraseComplexity",
        "acp": "C:123|I:123|A:123"
    },
    "...": "...",
    "meta_information": {
        "date": "2021-07-29T07:01:44.327867",
        "...": "..."
    },
    "profiles": {
        "all_rules": [
            "BL942-1101",
            "..."
        ]
    },
    "default_profile": "all_rules"
}
```

For guides targeting Windows, we generate a set of PowerShell commandlets together with a JSON file containing the necessary data used to implement or check the corresponding rule.
One can see such a JSON file [here](code/4_sfera_automation.json).

### Test Specification

```yaml
os_image: Windows10
os_image_version: 1809
ciscat_version: v4.0.20
testruns:
- name: 1809 L2 High Security (...)
- name: 1809_Level1_Corporate_General_use
  testrun_ps_profile: L1_Corp_Env_genUse
  testrun_ciscat_profile: cisbenchmarks_profile_L1_Corp_Env_genUse
  testrun_benchmark_filename: CIS_Win_10_1809-xccdf.xml
  activities:
  - id: initial_powershell_check
    type: ps_scripts
    sub_type: check_all
    validations:
    - sub_type: count
      expected:
        blacklist_rules: 0
        compliant_checks: 75
        non_compliant_checks: 272
        empty_checks: 2
        unknown_checks: 2
    (...)
  - id: apply_all
    type: ps_scripts
    sub_type: apply_all
    blacklist_rules: [R2_2_16, R2_3_1_1, ..., R18_9_97_2_4]
    validations:
    - sub_type: count
      expected:
        applied_automations: 336
        not_applied_automations: 4
    (...)
  - id: check-after-apply-all-with-ps
    type: ps_scripts
    sub_type: check_all
    validations:
    - sub_type: by_id
      result: non_compliant_checks
      comment: Correspond to blacklisted rules
      check_ids: [R2_2_16, R2_3_1_1, ..., R18_9_97_2_4]
    (...)
  - id: check_after_apply_all_ciscat ...
    type: ciscat
    validations:
    - sub_type: compare
      compare_with: check-after-apply-all-with-ps
      expected:
        comment: CISCAT error for 18.8.21.5
        rules_failed_only_here: [R18_8_21_5, ...]
        rules_unknown_only_here: [R1_1_5, R1_1_6, R2_3_10_1]
        rules_unknown_only_there: [R18_2_1, ...]
        rules_passed_only_here: []
    (...)
static:
- id: validate_json_file
  type: examine_sfera_automation_json
  validations:
  - sub_type: count
    expected:
      no_automation: 1
      (...)
  - sub_type: by_id
    expected:
      no_automation: [R18_2_1]
      same_setting: []
(...)
```

[This file](code/5_test_spec.yml) shows an exemplary test specification file.
Each test run specifies several activities with a list of validations per activity:

-   We specify two test runs (lines 5-6), one for the *Level 2*, i.e., high-security, profile of a CIS Windows 10 (1809) Benchmark, the other one for the basic *Level 1* profile.
    Here we only show parts of the latter.
-   We start with a check of the unchanged system, using the generated PowerShell scripts (line 11).
    The first validation activity (lines 15--21) provides a count of the check result:
    how many rules were compliant, non-compliant, et cetera.
    Here, as in all the following examples, the values defined in the test specification file are the expected values taken from previous test runs.
-   We continue using the generated PowerShell scripts to apply all rules (line 25) of the chosen *Level 1* profile (line 7).
    We usually need to blacklist some rules (line 26) because there are rules breaking the test mechanism, e.g., by disrupting connections to the test machine.
    Again, amongst other things, we validate the number of successfully applied rules (line 30).
-   We follow the rules' application with two check activities:
    we check with the generated PowerShell script (lines 33ff) and an external scanner provided by the CIS (lines 42ff).
    -   Here, we see an example of validating not just rule counts but
        the actual rule identifiers, e.g., as we examine the rules that
        our script reports as non-compliant (line 40). In line 39, a
        tester made a comment: the non-compliant rules correspond to the
        blacklisted rules (in line 26).
    -   We can also carry out other relevant comparisons automatically:
        For example, in lines 45ff., the check results of the CIS
        scanner are compared with the results of our PowerShell script;
        in line 49, under the keyword `rules_failed_only_here`, we see a
        list of rules which the CIS scanner reports as non-compliant,
        but our PowerShell scripts report as compliant. Again, a tester
        added a comment (line 48) about the reasons for the deviations.

        For example, for a specific rule, the CIS scanner requires that
        a particular setting should not be configured, even though the
        human-readable description of the rule requires that the setting
        should be disabled. Testers at re-discovered systematic false
        positives like these repeatedly; by documenting such problems of
        external scanners, testers can better focus on actual
        deviations.

-   We also carry out static tests on the created artifacts (line
    54ff.); the static tests are always carried out as the very first
    test activity. For example, we examine the created JSON file for
    entries without an automation (lines 60, 64) to catch errors during
    maintenance, leading to a failure when creating automations. Another
    valuable check is whether the same security setting is affected by
    several rules (line 65) since this often points to an error made
    during the rules' specification.

One can see an actual test specification file [here](./code/5_windows_10_spec.yml).


## Documentation of full results

```log
CRITICAL - Validation failed, SAME numbers, but DIFFERENT IDs (IMPROVEMENT: 'fall')!
 Expected and confirmed(found) 'unknown_checks' IDs: {'R18_2_1', 'R2_3_1_6', 'R2_2_21', 'R2_3_1_5'}
 Expected 'unknown_checks' IDs, but not found: {'R2_3_11_3'}
 Found 'unknown_checks' IDs, but not expected: {'R19_7_41_1'}
```

In case a deeper analysis of the results becomes necessary, the users
can access detailed information about found deviations for each
validation step:
[This file](code/6_report.txt) provides an example of how a
deviation is reported. Furthermore, users can access the raw data for
each activity within a staging repository containing the generated
artifacts. Thus, all relevant data are provided at one location. Also,
they can use different mechanisms provided by *git* and *GitLab* such as
viewing differences between test executions, e.g., within the generated
artifacts, during the analysis of the test results.

## Additional Resources

- Under [tum-i4/disa-windows-server-2016](https://github.com/tum-i4/disa-windows-server-2016) and [tum-i4/disa-windows-server-2019](https://github.com/tum-i4/disa-windows-server-2019) one can find two complete security-configuration guides in the Scapolite format.
- One can find an overview of our research [here](https://www.in.tum.de/en/hardening-security-configuration/).
- In February 2022, we presented parts of our approach (in German) at the [**29. DFN-Konferenz Sicherheit in vernetzten Systemen**](https://www.dfn-cert.de/veranstaltungen/Sicherheitskonferenz2022.html).
- In 2019, we presented parts of our approach at [NIST's SCAPv2 meeting](https://csrc.nist.gov/projects/Security-Content-Automation-Protocol-v2).
  One can find our presentation in the [Presentation Archives](https://csrc.nist.gov/projects/Security-Content-Automation-Protocol-v2).

## Contact

If you have any questions, please create an issue or contact [Patrick Stöckle](https://www.in.tum.de/en/i04/stoeckle/).
