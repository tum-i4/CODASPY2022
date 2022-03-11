---
scapolite:
    class: rule
    version: '0.51'
id: BL942-1101
id_namespace: com.siemens.seg.policy_framework.rule
title: Configure the policy 'Configure use of passwords for removable data drives'
rule: <see below>
rationale: <see below>
description: <see below>
applicability:
  - system: com.siemens.cert.acp
    c: '123'
    i: '123'
    a: '123'
  - system: com.siemens.cert.scapolite.target_audience
    roles:
      - asset_manager
implementations:
  - relative_id: '01'
    description: <see below>
    automations:
      - system: org.scapolite.implementation.win_gpo
        ui_path: Computer Configuration\Policies\Administrative Templates\Windows
            Components\BitLocker Drive Encryption\Removable Data Drives\Configure
            use of passwords for removable data drives
        value:
            main_setting: Enabled
            Configure password complexity for removable data drives: Require password
                complexity
            Minimum password length for removable data drive: 15
        constraints:
            sub_setting:
                Minimum password length for removable data drive:
                    min: 15
crossrefs:
  - system: com.siemens.seg.policy_framework.rule
    idref: 12.1.1-05
    relation: based_on
  - system: urn:scapolite:scce
    idref: gpo:computer:admx:windows_components:bitlocker_drive_encryption:removable_data_drives:configure_use_of_passwords_for_removable_data_drives
    relation: ''
history:
  - version: '1.0'
    eval: true
    action: created
    description: Not part of CIS Windows Server 2019 and Siemens Windows Server 2016
        (BL968). Rule has been copied from Siemens Windows 10 (BL696).
    internal_comment: Originally taken from Windows 10 Measure Plan.
---


## /rule

Enable the setting 'Configure use of passwords for removable data drives' and set the options as follows:

   *  Select the value `Require password complexity` in the drop-down list,
   *  Set the option 'Minimum password length for removable data drive' to `15`.

**Note:** The encryption password for removable data drives is exempt from the
password change requirements of the _Specific Information Security Policy: Access Control_
[Rule ID: 09.4.3-04](#scapolite_obj:com.siemens.seg.policy_framework.rule:09.4.3-04).

## /rationale

If an unencrypted USB memory stick or poorly configured (e.g., short password,
weak cipher, only used disk space encrypted) gets lost or stolen, any person
who finds the USB stick can plug in it to his or her computer and see the
content on the stick if it is unencrypted or try to access it by guessing the
password or exploiting a weakness of the cipher.

While a USB stick protected with a smart card can only be used if you have the
smart card and the associated PIN, a malicious user might try to discover the
password of an only password protected USB stick by using a brute-force attack.

## /description

Microsoft Windows includes the built-in full disk and volume encryption feature
BitLocker Drive Encryption (BDE) which, apart from encrypting fixed drives, can
be used to encrypt removable drives (also known as _BitLocker To Go_).

You can protect a _BitLocker To Go_ encrypted device either with a smart card,
a password, or with a combination of both.

## /implementations/0/description

To set the protection level to the desired state set the following Group Policy setting to `Enabled`

`Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Removable Data Drives\Configure use of passwords for removable data drives`

and set the options as follows:

   *  Select the value `Require password complexity` in the drop-down list,
   *  Set the option _Minimum password length for removable data drive_ to `15`.
